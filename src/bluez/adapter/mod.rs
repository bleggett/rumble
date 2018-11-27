mod acl_stream;
mod discoveredperipheral;
mod util;

use bytes::{BufMut, BytesMut};
use libc;
use nom;
use std;
use std::ffi::CStr;

use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use api::{
    BDAddr, Central, CentralEvent, Characteristic, CommandCallback, EventHandler,
    NotificationHandler, PeripheralDescriptor, RequestCallback, UUID,
};
use Error;
use Result;

use bluez::adapter::discoveredperipheral::DiscoveredPeripheral;
use bluez::constants::*;
use bluez::protocol::{att, hci};
use bluez::util::handle_error;

#[derive(Copy, Debug)]
#[repr(C)]
pub struct HCIDevStats {
    pub err_rx: u32,
    pub err_tx: u32,
    pub cmd_tx: u32,
    pub evt_rx: u32,
    pub acl_tx: u32,
    pub acl_rx: u32,
    pub sco_tx: u32,
    pub sco_rx: u32,
    pub byte_rx: u32,
    pub byte_tx: u32,
}

impl Clone for HCIDevStats {
    fn clone(&self) -> Self {
        *self
    }
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
            byte_tx: 0u32,
        }
    }
}

#[derive(Copy, Debug)]
#[repr(C)]
pub struct HCIDevInfo {
    pub dev_id: u16,
    pub name: [libc::c_char; 8],
    pub bdaddr: BDAddr,
    pub flags: u32,
    pub type_: u8,
    pub features: [u8; 8],
    pub pkt_type: u32,
    pub link_policy: u32,
    pub link_mode: u32,
    pub acl_mtu: u16,
    pub acl_pkts: u16,
    pub sco_mtu: u16,
    pub sco_pkts: u16,
    pub stat: HCIDevStats,
}

impl Clone for HCIDevInfo {
    fn clone(&self) -> Self {
        *self
    }
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
            stat: HCIDevStats::default(),
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
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Debug, Copy, Clone)]
pub enum AdapterType {
    BrEdr,
    Amp,
    Unknown(u8),
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
    Up,
    Init,
    Running,
    Raw,
    PScan,
    IScan,
    Inquiry,
    Auth,
    Encrypt,
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
            libc::bind(
                adapter_fd,
                &addr as *const SockaddrHCI as *const libc::sockaddr,
                std::mem::size_of::<SockaddrHCI>() as u32,
            )
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
        let event_mask1 = (1 << EVT_DISCONN_COMPLETE)
            | (1 << EVT_ENCRYPT_CHANGE)
            | (1 << EVT_CMD_COMPLETE)
            | (1 << EVT_CMD_STATUS);
        let event_mask2 = 1 << (EVT_LE_META_EVENT - 32);
        let opcode = 0;

        filter.put_u32_le(type_mask);
        filter.put_u32_le(event_mask1);
        filter.put_u32_le(event_mask2);
        filter.put_u16_le(opcode);

        handle_error(unsafe {
            libc::setsockopt(
                self.adapter_fd,
                SOL_HCI,
                HCI_FILTER,
                filter.as_mut_ptr() as *mut _ as *mut libc::c_void,
                filter.len() as u32,
            )
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
                debug!("reading");
                let len = handle_error(unsafe {
                    libc::read(
                        fd,
                        buf.as_mut_ptr() as *mut _ as *mut libc::c_void,
                        buf.len(),
                    ) as i32
                }).unwrap_or(0) as usize;
                if len == 0 {
                    debug!("Got nothing, continuing..");
                    continue;
                }

                cur.put_slice(&buf[0..len]);

                let mut new_cur: Option<Vec<u8>> = Some(vec![]);
                {
                    debug!("Converting buffer to message...");
                    let result = { hci::message(&cur) };

                    match result {
                        Ok((left, result)) => {
                            ConnectedAdapter::handle(&connected, result);
                            if !left.is_empty() {
                                new_cur = Some(left.to_owned());
                            };
                        }
                        Err(nom::Err::Incomplete(_)) => {
                            new_cur = None;
                        }
                        Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
                            error!("parse error {:?}\nfrom: {:?}", err, cur);
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
                    debug!("TRYLOCK LEAdvertisingReport");
                    let mut peripherals = self.peripherals.try_lock().unwrap();
                    let peripheral = peripherals.entry(info.bdaddr).or_insert_with(|| {
                        new = true;
                        debug!("Inserting new peripheral with addr {}", info.bdaddr);
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

                {
                    debug!("TRYLOCK LEConnComplete");
                    if let Entry::Occupied(mut peripheral) =
                        self.peripherals.try_lock().unwrap().entry(address)
                    {
                        peripheral
                            .get_mut()
                            .handle_device_message(&hci::Message::LEConnComplete(info));
                    } else {
                        warn!("Got connection for unknown device {}", info.bdaddr);
                    }
                }

                let mut handles = self.handle_map.try_lock().unwrap();
                handles.insert(handle, address);

                self.emit(CentralEvent::DeviceConnected(address));
            }
            hci::Message::ACLDataPacket(data) => {
                let message = hci::Message::ACLDataPacket(data);

                // TODO this is a bit risky from a deadlock perspective (note mutexes are not
                // reentrant in rust!)
                debug!("Bout to lock for ACLDataPacket");
                let mut peripherals = self.peripherals.lock().unwrap();

                for peripheral in peripherals.values_mut() {
                    // we don't know the handler => device mapping, so send to all and let them filter
                    debug!("sending to all devices");
                    peripheral.handle_device_message(&message);
                }
            }
            hci::Message::DisconnectComplete { handle, .. } => {
                let mut handles = self.handle_map.try_lock().unwrap();
                match handles.remove(&handle) {
                    Some(address) => {
                        debug!("TRYLOCK DisconnectComplete");
                        if let Entry::Occupied(mut peripheral) =
                            self.peripherals.try_lock().unwrap().entry(address)
                        {
                            peripheral.get_mut().handle_device_message(&message);
                        }
                        self.emit(CentralEvent::DeviceDisconnected(address));
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
            libc::write(
                self.adapter_fd,
                ptr as *mut _ as *mut libc::c_void,
                message.len(),
            ) as i32
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
}

impl PeripheralDescriptor {
    pub fn new(d_periph: &DiscoveredPeripheral) -> PeripheralDescriptor {
        d_periph.get_descriptor()
    }
}

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
        debug!("TRYLOCK peripherals");
        let l = self.peripherals.lock().unwrap();
        l.values().map(|p| PeripheralDescriptor::new(p)).collect()
    }

    fn peripheral(&self, address: BDAddr) -> Option<PeripheralDescriptor> {
        debug!("TRYLOCK peripheral");
        let l = self.peripherals.lock().unwrap();
        l.get(&address).map(|p| PeripheralDescriptor::new(p))
    }

    fn connect(&self, address: BDAddr) -> Result<()> {
        debug!("Connecting to {}", address);
        let test = {
            debug!("TRYLOCK connect");
            //TODO avoid clone
            match self.peripherals.lock().unwrap().entry(address) {
                Entry::Occupied(peripheral) => Ok(peripheral.get().clone()),
                Entry::Vacant(_) => Err(Error::DeviceNotFound),
            }
        };
        test.unwrap().connect()
        // let mut peripheral = {
        //     debug!("Locking peripherals in connect");
        //     match self.peripherals.entry(address) {
        //         Entry::Occupied(mut peripheral) => Ok(peripheral.get_mut()),
        //         Entry::Vacant(_) => Err(Error::DeviceNotFound),
        //     }
        // };
    }

    fn disconnect(&self, address: BDAddr) -> Result<()> {
        debug!("TRYLOCK disconnect");
        match self.peripherals.lock().unwrap().entry(address) {
            Entry::Occupied(mut peripheral) => peripheral.get_mut().disconnect(),
            Entry::Vacant(_) => Err(Error::DeviceNotFound),
        }
    }

    fn discover_characteristics(&self, address: BDAddr) -> Result<Vec<Characteristic>> {
        self.discover_characteristics_in_range(address, 0x0001, 0xFFFF)
    }

    fn discover_characteristics_in_range(
        &self,
        address: BDAddr,
        start: u16,
        end: u16,
    ) -> Result<Vec<Characteristic>> {
        let mut results = vec![];
        let mut start = start;

        let peripheral = {
            debug!("TRYLOCK discover-characteristics");
            match self.peripherals.lock().unwrap().entry(address) {
                Entry::Occupied(peripheral) => Ok(peripheral.get().clone()),
                Entry::Vacant(_) => Err(Error::DeviceNotFound),
            }
        }.unwrap();

        loop {
            debug!("discovering chars in range [{}, {}]", start, end);

            let mut buf = att::read_by_type_req(start, end, UUID::B16(GATT_CHARAC_UUID));

            // let data = match self.peripherals.try_lock().unwrap().entry(address) {
            //     Entry::Occupied(mut peripheral) => peripheral.get_mut().request_raw(&mut buf)?,
            //     Entry::Vacant(_) => Vec::new(),
            // };

            let data = peripheral.request_raw(&mut buf)?;

            match att::characteristics(&data) {
                Ok(result) => {
                    match result.1 {
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
                    return Err(Error::Other(format!(
                        "failed to parse characteristics response {:?}",
                        err
                    )));
                }
            }
        }

        // fix the end handles (we don't get them directly from device, so we have to infer)
        for i in 0..results.len() {
            (*results.get_mut(i).unwrap()).end_handle =
                results.get(i + 1).map(|c| c.end_handle).unwrap_or(end);
        }

        // update our cache
        debug!("TRYLOCK discover-characteristics update");
        if let Entry::Occupied(mut peripheral) = self.peripherals.lock().unwrap().entry(address) {
            debug!("Cloned chars: {:?}", results);
            peripheral.get_mut().update_characteristics(results.clone());
        }
        Ok(results)
    }

    fn command_async(
        &self,
        address: BDAddr,
        characteristic: &Characteristic,
        data: &[u8],
        handler: Option<CommandCallback>,
    ) {
        debug!("TRYLOCK command_async");
        if let Entry::Occupied(mut peripheral) = self.peripherals.lock().unwrap().entry(address) {
            peripheral
                .get_mut()
                .write_command(characteristic, data, handler)
        }
    }

    fn command(&self, address: BDAddr, characteristic: &Characteristic, data: &[u8]) -> Result<()> {
        util::wait_until_done(|done: CommandCallback| {
            self.command_async(address, characteristic, data, Some(done));
        })
    }

    fn request_async(
        &self,
        address: BDAddr,
        characteristic: &Characteristic,
        data: &[u8],
        handler: Option<RequestCallback>,
    ) {
        debug!("TRYLOCK request_async");
        if let Entry::Occupied(mut peripheral) = self.peripherals.lock().unwrap().entry(address) {
            peripheral
                .get_mut()
                .request_by_handle(characteristic.value_handle, data, handler);
        }
    }

    fn request(
        &self,
        address: BDAddr,
        characteristic: &Characteristic,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        util::wait_until_done(|done: RequestCallback| {
            self.request_async(address, characteristic, data, Some(done));
        })
    }

    fn read_by_type_async(
        &self,
        address: BDAddr,
        characteristic: &Characteristic,
        uuid: UUID,
        handler: Option<RequestCallback>,
    ) {
        let mut buf =
            att::read_by_type_req(characteristic.start_handle, characteristic.end_handle, uuid);
        debug!("TRYLOCK read_by_type_async");
        if let Entry::Occupied(mut peripheral) = self.peripherals.lock().unwrap().entry(address) {
            peripheral.get_mut().request_raw_async(&mut buf, handler);
        }
    }

    fn read_by_type(
        &self,
        address: BDAddr,
        characteristic: &Characteristic,
        uuid: UUID,
    ) -> Result<Vec<u8>> {
        util::wait_until_done(|done: RequestCallback| {
            self.read_by_type_async(address, characteristic, uuid, Some(done));
        })
    }

    fn subscribe(&self, address: BDAddr, characteristic: &Characteristic) -> Result<()> {
        debug!("TRYLOCK subscribe");
        match self.peripherals.lock().unwrap().entry(address) {
            Entry::Occupied(mut peripheral) => peripheral.get_mut().notify(characteristic, true),
            Entry::Vacant(_) => Err(Error::DeviceNotFound),
        }
    }

    fn unsubscribe(&self, address: BDAddr, characteristic: &Characteristic) -> Result<()> {
        debug!("TRYLOCK unsubscribe");
        match self.peripherals.lock().unwrap().entry(address) {
            Entry::Occupied(mut peripheral) => peripheral.get_mut().notify(characteristic, false),
            Entry::Vacant(_) => Err(Error::DeviceNotFound),
        }
    }

    fn on_notification(&self, address: BDAddr, handler: NotificationHandler) {
        debug!("TRYLOCK on_notification");
        if let Entry::Occupied(mut peripheral) = self.peripherals.lock().unwrap().entry(address) {
            peripheral.get_mut().add_notification(handler);
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
static HCI_GET_DEV_MAGIC: usize = (2u32 << 0i32 + 8i32 + 8i32 + 14i32
    | (b'H' as (i32) << 0i32 + 8i32) as (u32)
    | (211i32 << 0i32) as (u32)) as (usize)
    | 4 /* (sizeof(i32)) */ << 0i32 + 8i32 + 8i32;

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
            handle_error(libc::ioctl(
                ctl,
                HCI_GET_DEV_MAGIC as libc::c_ulong,
                &mut di as (*mut HCIDevInfo) as (*mut libc::c_void),
            ))?;
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
