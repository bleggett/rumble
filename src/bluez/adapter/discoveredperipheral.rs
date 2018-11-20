use Error;
use Result;

use api::{
    AddressType, BDAddr, Central, CharPropFlags, Characteristic, CommandCallback,
    NotificationHandler, PeripheralDescriptor, RequestCallback, UUID::B16,
};

use std::collections::{BTreeSet, VecDeque};
use std::mem::size_of;
use std::sync::{
    atomic::Ordering, mpsc, mpsc::channel, mpsc::Receiver, mpsc::Sender, Arc, Mutex, RwLock,
};
use std::time::Duration;
use std::{fmt, fmt::Debug, fmt::Display, fmt::Formatter};

use bytes::{BufMut, BytesMut};

use bluez::adapter::{acl_stream::ACLStream, util, ConnectedAdapter};
use bluez::constants::*;
use bluez::protocol::{att, hci, hci::ACLData};
use bluez::util::handle_error;

#[derive(Copy, Debug)]
#[repr(C)]
struct SockaddrL2 {
    l2_family: libc::sa_family_t,
    l2_psm: u16,
    l2_bdaddr: BDAddr,
    l2_cid: u16,
    l2_bdaddr_type: u32,
}

impl Clone for SockaddrL2 {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Copy, Debug, Default)]
#[repr(C)]
struct L2CapOptions {
    omtu: u16,
    imtu: u16,
    flush_to: u16,
    mode: u8,
    fcs: u8,
    max_tx: u8,
    txwin_size: u16,
}
impl Clone for L2CapOptions {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Clone)]
pub struct DiscoveredPeripheral {
    c_adapter: ConnectedAdapter,
    pub address: BDAddr,
    address_type: AddressType,
    local_name: String,
    tx_power_level: i8,
    manufacturer_data: Vec<u8>,
    discovery_count: u32,
    has_scan_response: bool,
    is_connected: bool,
    characteristics: BTreeSet<Characteristic>,
    stream: Arc<RwLock<Option<ACLStream>>>,
    connection_tx: Arc<Mutex<Sender<u16>>>,
    connection_rx: Arc<Mutex<Receiver<u16>>>,
    message_queue: Arc<Mutex<VecDeque<ACLData>>>,
}

impl Display for DiscoveredPeripheral {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let connected = if self.is_connected { " connected" } else { "" };
        write!(f, "{} {}{}", self.address, self.local_name, connected)
    }
}

impl Debug for DiscoveredPeripheral {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let connected = if self.is_connected { " connected" } else { "" };
        write!(
            f,
            "{} characteristics: {:?} {}",
            self.address, self.characteristics, connected
        )
    }
}

impl DiscoveredPeripheral {
    pub fn new(c_adapter: ConnectedAdapter, address: BDAddr) -> DiscoveredPeripheral {
        let (connection_tx, connection_rx) = channel();
        DiscoveredPeripheral {
            c_adapter,
            address,
            address_type: AddressType::Random,
            local_name: "(unknown)".into(),
            tx_power_level: 0,
            manufacturer_data: Vec::new(),
            discovery_count: 0,
            has_scan_response: false,
            is_connected: false,
            characteristics: BTreeSet::new(),
            stream: Arc::new(RwLock::new(Option::None)),
            connection_tx: Arc::new(Mutex::new(connection_tx)),
            connection_rx: Arc::new(Mutex::new(connection_rx)),
            message_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn update_characteristics(&mut self, newset: Vec<Characteristic>) {
        newset.iter().for_each(|c| {
            self.characteristics.insert(c.clone());
        });
    }

    pub fn handle_device_message(&mut self, message: &hci::Message) {
        match message {
            &hci::Message::LEAdvertisingReport(ref info) => {
                assert_eq!(
                    self.address, info.bdaddr,
                    "received message for wrong device"
                );
                use bluez::protocol::hci::LEAdvertisingData::*;

                self.discovery_count += 1;
                self.address_type = if info.bdaddr_type == 1 {
                    AddressType::Random
                } else {
                    AddressType::Public
                };

                self.address = info.bdaddr;

                if info.evt_type == 4 {
                    // discover event
                    self.has_scan_response = true;
                } else {
                    // TODO: reset service data
                }

                for datum in info.data.iter() {
                    match datum {
                        &LocalName(ref name) => {
                            self.local_name = name.clone();
                        }
                        &TxPowerLevel(ref power) => {
                            self.tx_power_level = power.clone();
                        }
                        &ManufacturerSpecific(ref data) => {
                            self.manufacturer_data = data.clone();
                        }
                        _ => {
                            // skip for now
                        }
                    }
                }
            }
            &hci::Message::LEConnComplete(ref info) => {
                assert_eq!(
                    self.address, info.bdaddr,
                    "received message for wrong device"
                );

                debug!("got le conn complete {:?}", info);
                self.connection_tx
                    .lock()
                    .unwrap()
                    .send(info.handle.clone())
                    .unwrap();
            }
            &hci::Message::ACLDataPacket(ref data) => {
                let handle = data.handle.clone();
                match self.stream.try_read() {
                    Ok(stream) => {
                        stream.iter().for_each(|stream| {
                            if stream.handle == handle {
                                debug!("got data packet for {}: {:?}", self.address, data);
                                stream.receive(data);
                            }
                        });
                    }
                    Err(_e) => {
                        // we can't access the stream right now because we're still connecting, so
                        // we'll push the message onto a queue for now
                        let mut queue = self.message_queue.lock().unwrap();
                        queue.push_back(data.clone());
                    }
                }
            }
            &hci::Message::DisconnectComplete { .. } => {
                // destroy our stream
                debug!("removing stream for {} due to disconnect", self.address);
                let mut stream = self.stream.write().unwrap();
                *stream = None;
                // TODO clean up our sockets
            }
            msg => {
                debug!("ignored message {:?}", msg);
            }
        }
    }

    pub fn request_raw_async(&self, data: &mut [u8], handler: Option<RequestCallback>) {
        let l = self.stream.read().unwrap();
        match l.as_ref().ok_or(Error::NotConnected) {
            Ok(stream) => {
                stream.write(&mut *data, handler);
            }
            Err(err) => {
                if let Some(h) = handler {
                    h(Err(err));
                }
            }
        }
    }

    pub fn request_raw(&self, data: &mut [u8]) -> Result<Vec<u8>> {
        util::wait_until_done(|done: RequestCallback| {
            // TODO this copy can be avoided
            let mut data = data.to_vec();
            self.request_raw_async(&mut data, Some(done));
        })
    }

    pub fn request_by_handle(&self, handle: u16, data: &[u8], handler: Option<RequestCallback>) {
        let mut buf = BytesMut::with_capacity(3 + data.len());
        buf.put_u8(ATT_OP_WRITE_REQ);
        buf.put_u16_le(handle);
        buf.put(data);
        self.request_raw_async(&mut buf, handler);
    }

    pub fn notify(&self, characteristic: &Characteristic, enable: bool) -> Result<()> {
        info!(
            "setting notify for {}/{:?} to {}",
            self.address, characteristic.uuid, enable
        );
        let mut buf = att::read_by_type_req(
            characteristic.start_handle,
            characteristic.end_handle,
            B16(GATT_CLIENT_CHARAC_CFG_UUID),
        );

        let data = self.request_raw(&mut buf)?;

        match att::notify_response(&data).to_result() {
            Ok(resp) => {
                let use_notify = characteristic.properties.contains(CharPropFlags::NOTIFY);
                let use_indicate = characteristic.properties.contains(CharPropFlags::INDICATE);

                let mut value = resp.value;

                if enable && use_notify {
                    value |= 0x0001;
                } else if enable && use_indicate {
                    value |= 0x0002;
                } else if use_notify {
                    value &= 0xFFFE;
                } else if use_indicate {
                    value &= 0xFFFD;
                }

                let mut value_buf = BytesMut::with_capacity(2);
                value_buf.put_u16_le(value);
                let data = util::wait_until_done(|done: RequestCallback| {
                    self.request_by_handle(resp.handle, &*value_buf, Some(done))
                })?;

                if data.len() > 0 && data[0] == ATT_OP_WRITE_RESP {
                    debug!("Got response from notify: {:?}", data);
                    Ok(())
                } else {
                    warn!("Unexpected notify response: {:?}", data);
                    Err(Error::Other("Failed to set notify".to_string()))
                }
            }
            Err(err) => {
                debug!("failed to parse notify response: {:?}", err);
                Err(Error::Other(
                    "failed to get characteristic state".to_string(),
                ))
            }
        }
    }

    pub fn connect(&self) -> Result<()> {
        let mut stream = self.stream.write().unwrap();

        if stream.is_some() {
            // we're already connected, just return
            return Ok(());
        }

        // create the socket on which we'll communicate with the device
        let fd =
            handle_error(unsafe { libc::socket(libc::AF_BLUETOOTH, libc::SOCK_SEQPACKET, 0) })?;
        debug!("created socket {} to communicate with device", fd);

        let local_addr = SockaddrL2 {
            l2_family: libc::AF_BLUETOOTH as libc::sa_family_t,
            l2_psm: 0,
            l2_bdaddr: self.c_adapter.adapter.addr,
            l2_cid: ATT_CID,
            l2_bdaddr_type: self.c_adapter.adapter.typ.num() as u32,
        };

        // bind to the socket
        handle_error(unsafe {
            libc::bind(
                fd,
                &local_addr as *const SockaddrL2 as *const libc::sockaddr,
                size_of::<SockaddrL2>() as u32,
            )
        })?;
        debug!("bound to socket {}", fd);

        // configure it as a bluetooth socket
        let mut opt = [1u8, 0];
        handle_error(unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_BLUETOOTH,
                4,
                opt.as_mut_ptr() as *mut libc::c_void,
                2,
            )
        })?;
        debug!("configured socket {}", fd);

        let addr = SockaddrL2 {
            l2_family: libc::AF_BLUETOOTH as u16,
            l2_psm: 0,
            l2_bdaddr: self.address,
            l2_cid: ATT_CID,
            l2_bdaddr_type: 1,
        };

        // connect to the device
        handle_error(unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrL2 as *const libc::sockaddr,
                size_of::<SockaddrL2>() as u32,
            )
        }).unwrap();
        debug!("connected to device {} over socket {}", self.address, fd);

        //TODO not a fan of reaching back up into the parent adapter to do this
        // restart scanning if we were already, as connecting to a device seems to kill it
        if self.c_adapter.scan_enabled.load(Ordering::Relaxed) {
            self.c_adapter.start_scan()?;
            debug!("restarted scanning");
        }

        // wait until we get the connection notice
        let timeout = Duration::from_secs(20);
        match self.connection_rx.lock().unwrap().recv_timeout(timeout) {
            Ok(handle) => {
                // create the acl stream that will communicate with the device
                let s = ACLStream::new(self.c_adapter.adapter.clone(), self.address, handle, fd);

                // replay missed messages
                let mut queue = self.message_queue.lock().unwrap();
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

    pub fn disconnect(&self) -> Result<()> {
        let mut l = self.stream.write().unwrap();

        if l.is_none() {
            // we're already disconnected
            return Ok(());
        }

        let handle = l.as_ref().unwrap().handle;

        let mut data = BytesMut::with_capacity(3);
        data.put_u16_le(handle);
        data.put_u8(HCI_OE_USER_ENDED_CONNECTION);
        let mut buf = hci::hci_command(DISCONNECT_CMD, &*data);
        self.c_adapter.write(&mut *buf)?;

        *l = None;
        Ok(())
    }

    pub fn write_command(
        &self,
        characteristic: &Characteristic,
        data: &[u8],
        handler: Option<CommandCallback>,
    ) {
        let l = self.stream.read().unwrap();

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

    pub fn add_notification(&self, handler: NotificationHandler) {
        // TODO handle the disconnected case better
        let l = self.stream.read().unwrap();
        match l.as_ref() {
            Some(stream) => {
                stream.on_notification(handler);
            }
            None => error!("tried to subscribe to notifications, but not yet connected"),
        }
    }

    pub fn get_descriptor(&self) -> PeripheralDescriptor {
        PeripheralDescriptor {
            address: self.address.clone(),
            address_type: self.address_type.clone(),
            local_name: Some(self.local_name.clone()),
            characteristics: self.characteristics.clone(),
            is_connected: self.is_connected,
            tx_power_level: Some(self.tx_power_level),
            manufacturer_data: Some(self.manufacturer_data.clone()),
            discovery_count: self.discovery_count,
        }
    }
}
