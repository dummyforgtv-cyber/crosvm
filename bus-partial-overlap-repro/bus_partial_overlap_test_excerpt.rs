    /// Reject accesses that start in-range but extend past the registration.
    ///
    /// Matching Firecracker `Bus::with_device`, dispatch requires the whole
    /// `[addr, addr+len)` to fit so device handlers need not re-check bounds.
    /// Live copy: `devices/src/bus.rs` test
    /// `bus_partial_overlap_past_device_range_is_rejected`.
    #[derive(Default)]
    struct RecordingDevice {
        /// (offset, len) of each read/write delivered by the bus.
        accesses: Vec<(u64, usize)>,
    }

    impl BusDevice for RecordingDevice {
        fn device_id(&self) -> DeviceId {
            PlatformDeviceId::Mock.into()
        }

        fn debug_label(&self) -> String {
            "recording device".to_owned()
        }

        fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
            self.accesses.push((info.offset, data.len()));
            for (i, b) in data.iter_mut().enumerate() {
                *b = 0xA0 + (i as u8);
            }
        }

        fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
            self.accesses.push((info.offset, data.len()));
        }
    }

    impl Suspendable for RecordingDevice {
        fn snapshot(&mut self) -> AnyhowResult<AnySnapshot> {
            AnySnapshot::to_any(0u8).context("error serializing")
        }
        fn restore(&mut self, _data: AnySnapshot) -> AnyhowResult<()> {
            Ok(())
        }
        fn sleep(&mut self) -> AnyhowResult<()> {
            Ok(())
        }
        fn wake(&mut self) -> AnyhowResult<()> {
            Ok(())
        }
    }

    #[test]
    fn bus_partial_overlap_past_device_range_is_rejected() {
        let bus = Bus::new(BusType::Mmio);
        let dev_a = Arc::new(Mutex::new(RecordingDevice::default()));
        let dev_b = Arc::new(Mutex::new(RecordingDevice::default()));

        // Device A: [0x1000, 0x1008). Device B adjacent: [0x1008, 0x1010).
        assert_eq!(bus.insert(dev_a.clone(), 0x1000, 8), Ok(()));
        assert_eq!(bus.insert(dev_b.clone(), 0x1008, 8), Ok(()));

        // 8-byte access starting 4 bytes before A's end spans into B; reject.
        let mut data = [0u8; 8];
        assert!(!bus.read(0x1004, &mut data));
        assert_eq!(data, [0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(dev_a.lock().accesses.is_empty());
        assert!(dev_b.lock().accesses.is_empty());

        assert!(!bus.write(0x1006, &[1, 2, 3, 4]));
        assert!(dev_a.lock().accesses.is_empty());
        assert!(dev_b.lock().accesses.is_empty());

        // Fully contained access still works.
        let mut in_range = [0u8; 4];
        assert!(bus.read(0x1000, &mut in_range));
        assert_eq!(in_range, [0xA0, 0xA1, 0xA2, 0xA3]);
        assert_eq!(dev_a.lock().accesses.last(), Some(&(0, 4)));
        assert!(dev_b.lock().accesses.is_empty());
    }
