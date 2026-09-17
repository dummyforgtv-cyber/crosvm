    /// Reproducer for the Firecracker `753888c` partial-overlap check gap.
    ///
    /// `Bus::get_device` only verifies that the access *start* lies inside a
    /// registered range (`bus.rs` get_device / contains). `Bus::read` /
    /// `Bus::write` then forward the entire `data` slice to that device with
    /// no check that `[addr, addr+data.len())` is contained in the range.
    /// Firecracker commit 753888c rejects such accesses at the bus layer.
    ///
    /// This test documents *current* crosvm behavior: the device whose range
    /// contains `addr` is still invoked, even when `addr + len` overruns the
    /// registration, and an adjacent device is *not* dispatched for the
    /// overrun bytes. That is a bus-API footgun; guest reachability of the
    /// same shape via KVM_EXIT_MMIO / KVM_EXIT_IO is analyzed separately
    /// (vcpu → handle_mmio/io → Bus::read/write with kvm-supplied len).
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
    fn bus_partial_overlap_past_device_range_still_dispatches() {
        let bus = Bus::new(BusType::Mmio);
        let dev_a = Arc::new(Mutex::new(RecordingDevice::default()));
        let dev_b = Arc::new(Mutex::new(RecordingDevice::default()));

        // Device A: [0x1000, 0x1008). Device B immediately adjacent: [0x1008, 0x1010).
        assert_eq!(bus.insert(dev_a.clone(), 0x1000, 8), Ok(()));
        assert_eq!(bus.insert(dev_b.clone(), 0x1008, 8), Ok(()));

        // 8-byte access starting 4 bytes before the end of A → spans into B's
        // address range on the bus map. Firecracker would reject this; crosvm
        // currently hands the full slice to A.
        let mut data = [0u8; 8];
        assert!(
            bus.read(0x1004, &mut data),
            "current tip: start-in-range partial overrun still returns true"
        );
        assert_eq!(data, [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]);

        {
            let a = dev_a.lock();
            assert_eq!(
                a.accesses,
                [(4, 8)],
                "device A called with offset=4, len=8 (4 bytes past its range)"
            );
        }
        {
            let b = dev_b.lock();
            assert!(
                b.accesses.is_empty(),
                "adjacent device B must not see the overrun bytes"
            );
        }

        // Same shape on write.
        assert!(bus.write(0x1006, &[1, 2, 3, 4]));
        {
            let a = dev_a.lock();
            assert_eq!(a.accesses.last(), Some(&(6, 4)));
        }
        {
            let b = dev_b.lock();
            assert!(b.accesses.is_empty());
        }

        // Fully contained access still works (control).
        let mut in_range = [0u8; 4];
        assert!(bus.read(0x1000, &mut in_range));
        assert_eq!(dev_a.lock().accesses.last(), Some(&(0, 4)));
    }
