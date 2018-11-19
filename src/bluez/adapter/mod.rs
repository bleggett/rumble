mod acl_stream;
mod discoveredperipheral;

use libc;
use std;
use std::ffi::CStr;
use std::mem::size_of;
use nom::IResult;
use bytes::{BytesMut, BufMut};

use std::collections::{HashSet, HashMap, hash_map::Entry};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread;

use ::Result;
use ::Error;
use api::{CentralEvent, Characteristic, BDAddr, Central, CommandCallback, RequestCallback, NotificationHandler, UUID, PeripheralDescriptor};

use bluez::util::handle_error;
use bluez::protocol::hci;
use bluez::protocol::att;
use bluez::adapter::acl_stream::{ACLStream};
use bluez::adapter::discoveredperipheral::DiscoveredPeripheral;
use bluez::constants::*;
use api::EventHandler;

#[derive(Copy, Debug)]
#[repr(C)]
pub struct HCIDevStats {
    pub err_rx : u32,
    pub err_tx : u32,
    pub cmd_tx : u32,
    pub evt_rx : u32,
    pub acl_tx : u32,
    pub acl_rx : u32,
    pub sco_tx : u32,
    pub sco_rx : u32,
    pub byte_rx : u32,
    pub byte_tx : u32,
}

impl Clone for HCIDevStats{
    fn clone(&self) -> Self { *self }
}

impl HCIDevStats {
    fn default() -> HCIDevStats {
        HCIDevStats {
            err_rx: 0u32,
            err_tx: 0u32,
            cmd_tx: 0u32,
            evt_rx: 0u32,
            acl_tx: 0u32,
            acl_rx: 0u32,
            sco_tx: 0u32,
            sco_rx: 0u32,
            byte_rx: 0u32,
            byte_tx: 0u32
        }
    }
}

#[derive(Copy, Debug)]
#[repr(C)]
pub struct SockaddrL2 {
    l2_family: libc::sa_family_t,
    l2_psm: u16,
    l2_bdaddr: BDAddr,
    l2_cid: u16,
    l2_bdaddr_type: u32,
}

impl Clone for SockaddrL2 {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy, Debug)]
#[repr(C)]
pub struct HCIDevInfo {
    pub dev_id : u16,
    pub name : [libc::c_char; 8],
    pub bdaddr : BDAddr,
    pub flags : u32,
    pub type_ : u8,
    pub features : [u8; 8],
    pub pkt_type : u32,
    pub link_policy : u32,
    pub link_mode : u32,
    pub acl_mtu : u16,
    pub acl_pkts : u16,
    pub sco_mtu : u16,
    pub sco_pkts : u16,
    pub stat : HCIDevStats,
}

impl Clone for HCIDevInfo {
    fn clone(&self) -> Self { *self }
}

impl HCIDevInfo {
    pub fn default() -> HCIDevInfo {
        HCIDevInfo {
            dev_id: 0,
            name: [0 as libc::c_char; 8],
            bdaddr: BDAddr { address: [0u8; 6] },
            flags: 0u32,
            type_: 0u8,
            features: [0u8; 8],
            pkt_type: 0u32,
            link_policy: 0u32,
            link_mode: 0u32,
            acl_mtu: 0u16,
            acl_pkts: 0u16,
            sco_mtu: 0u16,
            sco_pkts: 0u16,
            stat: HCIDevStats::default()
        }
    }
}

#[derive(Copy, Debug)]
#[repr(C)]
struct SockaddrHCI {
    hci_family: libc::sa_family_t,
    hci_dev: u16,
    hci_channel: u16,
}

impl Clone for SockaddrHCI {
    fn clone(&self) -> Self { *self }
}


#[derive(Debug, Copy, Clone)]
pub enum AdapterType {
    BrEdr,
    Amp,
    Unknown(u8)
}

impl AdapterType {
    fn parse(typ: u8) -> AdapterType {
        match typ {
            0 => AdapterType::BrEdr,
            1 => AdapterType::Amp,
            x => AdapterType::Unknown(x),
        }
    }

    fn num(&self) -> u8 {
        match *self {
            AdapterType::BrEdr => 0,
            AdapterType::Amp => 1,
            AdapterType::Unknown(x) => x,
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub enum AdapterState {
    Up, Init, Running, Raw, PScan, IScan, Inquiry, Auth, Encrypt
}

impl AdapterState {
    fn parse(flags: u32) -> HashSet<AdapterState> {
        use self::AdapterState::*;

        let states = [Up, Init, Running, Raw, PScan, IScan, Inquiry, Auth, Encrypt];

        let mut set = HashSet::new();
        for (i, f) in states.iter().enumerate() {
            if flags & (1 << (i & 31)) != 0 {
                set.insert(f.clone());
            }
        }

        set
    }
}

/// The [`Central`](../../api/trait.Central.html) implementation for BlueZ.
#[derive(Clone)]
pub struct ConnectedAdapter {
    pub adapter: Adapter,
    adapter_fd: i32,
    should_stop: Arc<AtomicBool>,
    pub scan_enabled: Arc<AtomicBool>,
    peripherals: Arc<Mutex<HashMap<BDAddr, DiscoveredPeripheral>>>,
    handle_map: Arc<Mutex<HashMap<u16, BDAddr>>>,
    event_handlers: Arc<Mutex<Vec<EventHandler>>>,
}

//TODO remove `unwrap`s
impl ConnectedAdapter {
    pub fn new(adapter: &Adapter) -> Result<ConnectedAdapter> {
        let adapter_fd = handle_error(unsafe {
            libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 1)
        })?;

        let addr = SockaddrHCI {
            hci_family: libc::AF_BLUETOOTH as u16,
            hci_dev: adapter.dev_id,
            hci_channel: 0,
        };

        handle_error(unsafe {
            libc::bind(adapter_fd, &addr as *const SockaddrHCI as *const libc::sockaddr,
                       std::mem::size_of::<SockaddrHCI>() as u32)
        })?;

        let should_stop = Arc::new(AtomicBool::new(false));

        let connected = ConnectedAdapter {
            adapter: adapter.clone(),
            adapter_fd,
            should_stop,
            scan_enabled: Arc::new(AtomicBool::new(false)),
            event_handlers: Arc::new(Mutex::new(vec![])),
            peripherals: Arc::new(Mutex::new(HashMap::new())),
            handle_map: Arc::new(Mutex::new(HashMap::new())),
        };

        connected.add_raw_socket_reader(adapter_fd);

        connected.set_socket_filter()?;

        Ok(connected)
    }

    fn set_socket_filter(&self) -> Result<()> {
        let mut filter = BytesMut::with_capacity(14);
        let type_mask = (1 << HCI_COMMAND_PKT) | (1 << HCI_EVENT_PKT) | (1 << HCI_ACLDATA_PKT);
        let event_mask1 = (1 << EVT_DISCONN_COMPLETE) | (1 << EVT_ENCRYPT_CHANGE) |
            (1 << EVT_CMD_COMPLETE) | (1 << EVT_CMD_STATUS);
        let event_mask2 = 1 << (EVT_LE_META_EVENT - 32);
        let opcode = 0;

        filter.put_u32_le(type_mask);
        filter.put_u32_le(event_mask1);
        filter.put_u32_le(event_mask2);
        filter.put_u16_le(opcode);

        handle_error(unsafe {
            libc::setsockopt(self.adapter_fd, SOL_HCI, HCI_FILTER,
                             filter.as_mut_ptr() as *mut _ as *mut libc::c_void,
                             filter.len() as u32)
        })?;
        Ok(())
    }

    fn add_raw_socket_reader(&self, fd: i32) {
        let should_stop = self.should_stop.clone();
        let connected = self.clone();

        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut cur: Vec<u8> = vec![];

            while !should_stop.load(Ordering::Relaxed) {
                // debug!("reading");
                let len = handle_error(unsafe {
                    libc::read(fd, buf.as_mut_ptr() as *mut _ as *mut libc::c_void, buf.len()) as i32
                }).unwrap_or(0) as usize;
                if len == 0 {
                    continue;
                }

                cur.put_slice(&buf[0..len]);

                let mut new_cur: Option<Vec<u8>> = Some(vec![]);
                {
                    let result = {
                        hci::message(&cur)
                    };

                    match result {
                        IResult::Done(left, result) => {
                            ConnectedAdapter::handle(&connected, result);
                            if !left.is_empty() {
                                new_cur = Some(left.to_owned());
                            };
                        }
                        IResult::Incomplete(_) => {
                            new_cur = None;
                        },
                        IResult::Error(err) => {
                            error!("parse error {}\nfrom: {:?}", err, cur);
                        }
                    }
                };

                cur = new_cur.unwrap_or(cur);
            }
        });
    }

    fn emit(&self, event: CentralEvent) {
        debug!("emitted {:?}", event);
        let handlers = self.event_handlers.clone();
        let vec = handlers.lock().unwrap();
        for handler in (*vec).iter() {
            handler(event.clone());
        }
    }

    fn handle(&self, message: hci::Message) {
        debug!("got message {:?}", message);

        match message {
            hci::Message::LEAdvertisingReport(info) => {
                let mut new = false;
                let address = info.bdaddr.clone();

                {
                    let mut peripherals = self.peripherals.lock().unwrap();
                    let peripheral = peripherals.entry(info.bdaddr)
                        .or_insert_with(|| {
                            new = true;
                            DiscoveredPeripheral::new(self.clone(), info.bdaddr)
                        });


                    peripheral.handle_device_message(&hci::Message::LEAdvertisingReport(info));
                }

                if new {
                    self.emit(CentralEvent::DeviceDiscovered(address.clone()))
                } else {
                    self.emit(CentralEvent::DeviceUpdated(address.clone()))
                }
            }
            hci::Message::LEConnComplete(info) => {
                info!("connected to {:?}", info);
                let address = info.bdaddr.clone();
                let handle = info.handle.clone();
                let mut peripheral = self.get_discovered_peripheral(address);

                    // Some(peripheral) => {
                peripheral.handle_device_message(&hci::Message::LEConnComplete(info));
                    // }
                    // todo: there's probably a better way to handle this case
                    // None => warn!("Got connection for unknown device {}", info.bdaddr)

                let mut handles = self.handle_map.lock().unwrap();
                handles.insert(handle, address);

                self.emit(CentralEvent::DeviceConnected(address));
            }
            hci::Message::ACLDataPacket(data) => {
                let message = hci::Message::ACLDataPacket(data);

                // TODO this is a bit risky from a deadlock perspective (note mutexes are not
                // reentrant in rust!)
                let mut peripherals = self.peripherals.lock().unwrap();

                for peripheral in peripherals.values_mut() {
                    // we don't know the handler => device mapping, so send to all and let them filter
                    peripheral.handle_device_message(&message);
                }
            },
            hci::Message::DisconnectComplete { handle, .. } => {
                let mut handles = self.handle_map.lock().unwrap();
                match handles.remove(&handle) {
                    Some(addr) => {
                        let mut peripheral = self.get_discovered_peripheral(addr);
                        peripheral.handle_device_message(&message);
                        self.emit(CentralEvent::DeviceDisconnected(addr));
                    }
                    None => {
                        warn!("got disconnect for unknown handle {}", handle);
                    }
                }
            }
            _ => {
                // skip
            }
        }
    }

    fn write(&self, message: &mut [u8]) -> Result<()> {
        debug!("writing({}) {:?}", self.adapter_fd, message);
        let ptr = message.as_mut_ptr();
        handle_error(unsafe {
            libc::write(self.adapter_fd, ptr as *mut _ as *mut libc::c_void, message.len()) as i32
        })?;
        Ok(())
    }

    fn set_scan_params(&self) -> Result<()> {
        let mut data = BytesMut::with_capacity(7);
        data.put_u8(1); // scan_type = active
        data.put_u16_le(0x0010); // interval ms
        data.put_u16_le(0x0010); // window ms
        data.put_u8(0); // own_type = public
        data.put_u8(0); // filter_policy = public
        let mut buf = hci::hci_command(LE_SET_SCAN_PARAMETERS_CMD, &*data);
        self.write(&mut *buf)
    }

    fn set_scan_enabled(&self, enabled: bool) -> Result<()> {
        let mut data = BytesMut::with_capacity(2);
        data.put_u8(if enabled { 1 } else { 0 }); // enabled
        data.put_u8(1); // filter duplicates

        self.scan_enabled.clone().store(enabled, Ordering::Relaxed);
        let mut buf = hci::hci_command(LE_SET_SCAN_ENABLE_CMD, &*data);
        self.write(&mut *buf)
    }



    fn get_discovered_peripheral(&self, address: BDAddr) -> DiscoveredPeripheral {
        // let l = self.peripherals.lock();
        // let res = l.unwrap();
        // MutexGuardRef::new(self.peripherals.get_mut().unwrap())
        self.peripherals.lock().unwrap().get(&address).unwrap().clone()
    }
}

impl PeripheralDescriptor {
    pub fn new(d_periph: &DiscoveredPeripheral) -> PeripheralDescriptor {
        d_periph.get_descriptor()
    }
}

// TODO This Central trait has nothing to do with the Peripheral struct/trait.
// it *should* be constrained to a ConnectedAdapter
// pub trait Central<C : Peripheral>: Send + Sync + Clone {
impl Central for ConnectedAdapter {
    fn on_event(&self, handler: EventHandler) {
        let list = self.event_handlers.clone();
        list.lock().unwrap().push(handler);
    }

    fn start_scan(&self) -> Result<()> {
        self.set_scan_params()?;
        self.set_scan_enabled(true)
    }

    fn stop_scan(&self) -> Result<()> {
        self.set_scan_enabled(false)
    }

    fn peripherals(&self) -> Vec<PeripheralDescriptor> {
        let l = self.peripherals.lock().unwrap();
        l.values().map(|p| PeripheralDescriptor::new(p)).collect()
    }

    fn peripheral(&self, address: BDAddr) -> Option<PeripheralDescriptor> {
        let l = self.peripherals.lock().unwrap();
        l.get(&address).map(|p| PeripheralDescriptor::new(p))
    }

    fn connect(&self, address: BDAddr) -> Result<()> {
        let peripheral = self.get_discovered_peripheral(address);
        // take lock on stream
        let mut stream = peripheral.stream.write().unwrap();

        if stream.is_some() {
            // we're already connected, just return
            return Ok(());
        }

        // create the socket on which we'll communicate with the device
        let fd = handle_error(unsafe {
            libc::socket(libc::AF_BLUETOOTH, libc::SOCK_SEQPACKET, 0)
        })?;
        debug!("created socket {} to communicate with device", fd);

        let local_addr = SockaddrL2 {
            l2_family: libc::AF_BLUETOOTH as libc::sa_family_t,
            l2_psm: 0,
            l2_bdaddr: self.adapter.addr,
            l2_cid: ATT_CID,
            l2_bdaddr_type: self.adapter.typ.num() as u32,
        };

        // bind to the socket
        handle_error(unsafe {
            libc::bind(fd, &local_addr as *const SockaddrL2 as *const libc::sockaddr,
                       size_of::<SockaddrL2>() as u32)
        })?;
        debug!("bound to socket {}", fd);

        // configure it as a bluetooth socket
        let mut opt = [1u8, 0];
        handle_error(unsafe {
            libc::setsockopt(fd, libc::SOL_BLUETOOTH, 4, opt.as_mut_ptr() as *mut libc::c_void, 2)
        })?;
        debug!("configured socket {}", fd);

        let addr = SockaddrL2 {
            l2_family: libc::AF_BLUETOOTH as u16,
            l2_psm: 0,
            l2_bdaddr: peripheral.address,
            l2_cid: ATT_CID,
            l2_bdaddr_type: 1,
        };

        // connect to the device
        handle_error(unsafe {
            libc::connect(fd, &addr as *const SockaddrL2 as *const libc::sockaddr,
                          size_of::<SockaddrL2>() as u32)
        }).unwrap();
        debug!("connected to device {} over socket {}", peripheral.address, fd);

        // restart scanning if we were already, as connecting to a device seems to kill it
        if self.scan_enabled.load(Ordering::Relaxed) {
            self.start_scan()?;
            debug!("restarted scanning");
        }

        // wait until we get the connection notice
        let timeout = Duration::from_secs(20);
        match peripheral.connection_rx.lock().unwrap().recv_timeout(timeout) {
            Ok(handle) => {
                // create the acl stream that will communicate with the device
                let s = ACLStream::new(self.adapter.clone(),
                                       peripheral.address, handle, fd);

                // replay missed messages
                let mut queue = peripheral.message_queue.lock().unwrap();
                while !queue.is_empty() {
                    let msg = queue.pop_back().unwrap();
                    if s.handle == msg.handle {
                        s.receive(&msg);
                    }
                }

                *stream = Some(s);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(Error::TimedOut(timeout.clone()));
            }
            err => {
                // unexpected error
                err.unwrap();
            }
        };

        Ok(())
    }

    fn disconnect(&self, address: BDAddr) -> Result<()> {
        let peripheral = self.get_discovered_peripheral(address);
        let mut l = peripheral.stream.write().unwrap();

        if l.is_none() {
            // we're already disconnected
            return Ok(());
        }

        let handle = l.as_ref().unwrap().handle;

        let mut data = BytesMut::with_capacity(3);
        data.put_u16_le(handle);
        data.put_u8(HCI_OE_USER_ENDED_CONNECTION);
        let mut buf = hci::hci_command(DISCONNECT_CMD, &*data);
        self.write(&mut *buf)?;

        *l = None;
        Ok(())
    }

    fn discover_characteristics(&self, address: BDAddr) -> Result<Vec<Characteristic>> {
        self.discover_characteristics_in_range(address, 0x0001, 0xFFFF)
    }

    fn discover_characteristics_in_range(&self, address: BDAddr, start: u16, end: u16) -> Result<Vec<Characteristic>> {
        let peripheral = self.get_discovered_peripheral(address);
        let mut results = vec![];
        let mut start = start;
        loop {
            debug!("discovering chars in range [{}, {}]", start, end);

            let mut buf = att::read_by_type_req(start, end, UUID::B16(GATT_CHARAC_UUID));
            let data = peripheral.request_raw(&mut buf)?;

            match att::characteristics(&data).to_result() {
                Ok(result) => {
                    match result {
                        Ok(chars) => {
                            debug!("Chars: {:#?}", chars);

                            // TODO this copy can be removed
                            results.extend(chars.clone());

                            if let Some(ref last) = chars.iter().last() {
                                if last.start_handle < end - 1 {
                                    start = last.start_handle + 1;
                                    continue;
                                }
                            }
                            break;
                        }
                        Err(err) => {
                            // this generally means we should stop iterating
                            debug!("got error: {:?}", err);
                            break;
                        }
                    }
                }
                Err(err) => {
                    error!("failed to parse chars: {:?}", err);
                    return Err(Error::Other(format!("failed to parse characteristics response {:?}",
                                                    err)));
                }
            }
        }

        // fix the end handles (we don't get them directly from device, so we have to infer)
        for i in 0..results.len() {
            (*results.get_mut(i).unwrap()).end_handle =
                results.get(i + 1).map(|c| c.end_handle).unwrap_or(end);
        }

        // update our cache
        if let Entry::Occupied(mut o) = self.peripherals.lock().unwrap().entry(address) {
            o.get_mut().update_characteristics(results.clone());
        }

        Ok(results)
    }

    fn command_async(&self, address: BDAddr, characteristic: &Characteristic, data: &[u8], handler: Option<CommandCallback>) {
        let peripheral = self.get_discovered_peripheral(address);
        let l = peripheral.stream.read().unwrap();

        match l.as_ref() {
            Some(stream) => {
                let mut buf = BytesMut::with_capacity(3 + data.len());
                buf.put_u8(ATT_OP_WRITE_CMD);
                buf.put_u16_le(characteristic.value_handle);
                buf.put(data);

                stream.write_cmd(&mut *buf, handler);
            }
            None => {
                handler.iter().for_each(|h| h(Err(Error::NotConnected)));
            }
        }
    }

    fn command(&self, address: BDAddr, characteristic: &Characteristic, data: &[u8]) -> Result<()> {
        DiscoveredPeripheral::wait_until_done(|done: CommandCallback| {
            self.command_async(address, characteristic, data, Some(done));
        })
    }

    fn request_async(&self, address: BDAddr, characteristic: &Characteristic, data: &[u8], handler: Option<RequestCallback>) {
        let peripheral = self.get_discovered_peripheral(address);
        peripheral.request_by_handle(characteristic.value_handle, data, handler);
    }

    fn request(&self, address: BDAddr, characteristic: &Characteristic, data: &[u8]) -> Result<Vec<u8>> {
        DiscoveredPeripheral::wait_until_done(|done: RequestCallback| {
            self.request_async(address, characteristic, data, Some(done));
        })
    }

    fn read_by_type_async(&self, address: BDAddr, characteristic: &Characteristic, uuid: UUID,
                          handler: Option<RequestCallback>) {
        let peripheral = self.get_discovered_peripheral(address);
        let mut buf = att::read_by_type_req(characteristic.start_handle, characteristic.end_handle, uuid);
        peripheral.request_raw_async(&mut buf, handler);
    }

    fn read_by_type(&self, address: BDAddr, characteristic: &Characteristic, uuid: UUID) -> Result<Vec<u8>> {
        DiscoveredPeripheral::wait_until_done(|done: RequestCallback| {
            self.read_by_type_async(address, characteristic, uuid, Some(done));
        })
    }

    fn subscribe(&self, address: BDAddr, characteristic: &Characteristic) -> Result<()> {
        let peripheral = self.get_discovered_peripheral(address);
        peripheral.notify(characteristic, true)
    }

    fn unsubscribe(&self, address: BDAddr, characteristic: &Characteristic) -> Result<()> {
        let peripheral = self.get_discovered_peripheral(address);
        peripheral.notify(characteristic, false)
    }

    fn on_notification(&self, address: BDAddr, handler: NotificationHandler) {
        let peripheral = self.get_discovered_peripheral(address);

        // TODO handle the disconnected case better
        let l = peripheral.stream.read().unwrap();
        match l.as_ref() {
            Some(stream) => {
                stream.on_notification(handler);
            }
            None => {
                error!("tried to subscribe to notifications, but not yet connected")
            }
        }
    }
}

/// Adapter represents a physical bluetooth interface in your system, for example a bluetooth
/// dongle.
#[derive(Debug, Clone)]
pub struct Adapter {
    /// The name of the adapter.
    pub name: String,

    /// The device id of the adapter.
    pub dev_id: u16,

    /// The address of the adapter.
    pub addr: BDAddr,

    /// The type of the adapater.
    pub typ: AdapterType,

    /// The set of states that the adapater is in.
    pub states: HashSet<AdapterState>,

    /// Properties of the adapter.
    pub info: HCIDevInfo,
}

// #define HCIGETDEVINFO	_IOR('H', 211, int)
static HCI_GET_DEV_MAGIC: usize = (2u32 << 0i32 + 8i32 + 8i32 + 14i32 |
    (b'H' as (i32) << 0i32 + 8i32) as (u32) | (211i32 << 0i32) as (u32)) as (usize) |
    4 /* (sizeof(i32)) */ << 0i32 + 8i32 + 8i32;

impl Adapter {
    pub fn from_device_info(di: &HCIDevInfo) -> Adapter {
        info!("DevInfo: {:?}", di);
        Adapter {
            name: String::from(unsafe { CStr::from_ptr(di.name.as_ptr()).to_str().unwrap() }),
            dev_id: 0,
            addr: di.bdaddr,
            typ: AdapterType::parse((di.type_ & 0x30) >> 4),
            states: AdapterState::parse(di.flags),
            info: di.clone(),
        }
    }

    pub fn from_dev_id(ctl: i32, dev_id: u16) -> Result<Adapter> {
        let mut di = HCIDevInfo::default();
        di.dev_id = dev_id;

        unsafe {
            handle_error(libc::ioctl(ctl, HCI_GET_DEV_MAGIC as libc::c_ulong,
                                     &mut di as (*mut HCIDevInfo) as (*mut libc::c_void)))?;
        }

        Ok(Adapter::from_device_info(&di))
    }

    pub fn is_up(&self) -> bool {
        self.states.contains(&AdapterState::Up)
    }

    pub fn connect(&self) -> Result<ConnectedAdapter> {
        ConnectedAdapter::new(self)
    }
}
