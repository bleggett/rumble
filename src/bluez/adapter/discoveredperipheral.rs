use ::Result;

use api::{Characteristic, CharPropFlags, Callback, BDAddr, PeripheralDescriptor};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use bluez::adapter::acl_stream::{ACLStream};
use bluez::adapter::ConnectedAdapter;
use bluez::constants::*;
use ::Error;
use bluez::protocol::hci;
use api::AddressType;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::channel;
use bytes::{BytesMut, BufMut};
use bluez::protocol::att;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt;
use std::sync::RwLock;
use std::collections::VecDeque;
use bluez::protocol::hci::ACLData;
use std::sync::Condvar;
use api::RequestCallback;
use api::UUID::B16;
use std::fmt::Display;


#[derive(Copy, Debug, Default)]
#[repr(C)]
struct L2CapOptions {
    omtu: u16,
    imtu: u16,
    flush_to: u16,
    mode: u8,
    fcs : u8,
    max_tx: u8,
    txwin_size: u16,
}
impl Clone for L2CapOptions {
    fn clone(&self) -> Self { *self }
}

#[derive(Clone)]
//TODO fix pub fields
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
    pub stream: Arc<RwLock<Option<ACLStream>>>,
    connection_tx: Arc<Mutex<Sender<u16>>>,
    pub connection_rx: Arc<Mutex<Receiver<u16>>>,
    pub message_queue: Arc<Mutex<VecDeque<ACLData>>>,
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
        write!(f, "{} characteristics: {:?} {}", self.address,
               self.characteristics, connected)
    }
}

impl DiscoveredPeripheral {
    pub fn new(c_adapter: ConnectedAdapter, address: BDAddr) -> DiscoveredPeripheral {
        let (connection_tx, connection_rx) = channel();
        DiscoveredPeripheral {
            c_adapter, address,
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

        newset.iter().for_each(|c| { self.characteristics.insert(c.clone());});
    }

    pub fn handle_device_message(&mut self, message: &hci::Message) {
        match message {
            &hci::Message::LEAdvertisingReport(ref info) => {
                assert_eq!(self.address, info.bdaddr, "received message for wrong device");
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
                assert_eq!(self.address, info.bdaddr, "received message for wrong device");

                debug!("got le conn complete {:?}", info);
                self.connection_tx.lock().unwrap().send(info.handle.clone()).unwrap();
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
            },
            &hci::Message::DisconnectComplete {..} => {
                // destroy our stream
                debug!("removing stream for {} due to disconnect", self.address);
                let mut stream = self.stream.write().unwrap();
                *stream = None;
                // TODO clean up our sockets
            },
            msg => {
                debug!("ignored message {:?}", msg);
            }
        }
    }

    pub fn request_raw_async(&self, data: &mut[u8], handler: Option<RequestCallback>) {
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
        DiscoveredPeripheral::wait_until_done(|done: RequestCallback| {
            // TODO this copy can be avoided
            let mut data = data.to_vec();
            self.request_raw_async(&mut data, Some(done));
        })
    }

    //TODO fix need to be public
    pub fn request_by_handle(&self, handle: u16, data: &[u8], handler: Option<RequestCallback>) {
        let mut buf = BytesMut::with_capacity(3 + data.len());
        buf.put_u8(ATT_OP_WRITE_REQ);
        buf.put_u16_le(handle);
        buf.put(data);
        self.request_raw_async(&mut buf, handler);
    }

    pub fn notify(&self, characteristic: &Characteristic, enable: bool) -> Result<()> {
        info!("setting notify for {}/{:?} to {}", self.address, characteristic.uuid, enable);
        let mut buf = att::read_by_type_req(
            characteristic.start_handle, characteristic.end_handle, B16(GATT_CLIENT_CHARAC_CFG_UUID));

        let data = self.request_raw(&mut buf)?;

        match att::notify_response(&data).to_result() {
            Ok(resp) => {
                let use_notify = characteristic.properties.contains(CharPropFlags::NOTIFY);
                let use_indicate = characteristic.properties.contains(CharPropFlags::INDICATE);

                let mut value = resp.value;

                if enable {
                    if use_notify {
                        value |= 0x0001;
                    } else if use_indicate {
                        value |= 0x0002;
                    }
                } else {
                    if use_notify {
                        value &= 0xFFFE;
                    } else if use_indicate {
                        value &= 0xFFFD;
                    }
                }

                let mut value_buf = BytesMut::with_capacity(2);
                value_buf.put_u16_le(value);
                let data = DiscoveredPeripheral::wait_until_done(|done: RequestCallback| {
                    self.request_by_handle(resp.handle, &*value_buf, Some(done))
                })?;

                if data.len() > 0 && data[0] == ATT_OP_WRITE_RESP {
                    debug!("Got response from notify: {:?}", data);
                    return Ok(());
                } else {
                    warn!("Unexpected notify response: {:?}", data);
                    return Err(Error::Other("Failed to set notify".to_string()));
                }
            }
            Err(err) => {
                debug!("failed to parse notify response: {:?}", err);
                return Err(Error::Other("failed to get characteristic state".to_string()));
            }
        };
    }

    //TODO fix pub methods
    pub fn wait_until_done<F, T: Clone + Send + 'static>(operation: F) -> Result<T> where F: for<'a> Fn(Callback<T>) {
        let pair = Arc::new((Mutex::new(None), Condvar::new()));
        let pair2 = pair.clone();
        let on_finish = Box::new(move|result: Result<T>| {
            let &(ref lock, ref cvar) = &*pair2;
            let mut done = lock.lock().unwrap();
            *done = Some(result.clone());
            cvar.notify_one();
        });

        operation(on_finish);

        // wait until we're done
        let &(ref lock, ref cvar) = &*pair;

        let mut done = lock.lock().unwrap();
        while (*done).is_none() {
            done = cvar.wait(done).unwrap();
        }

        // TODO: this copy is avoidable
        (*done).clone().unwrap()
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
