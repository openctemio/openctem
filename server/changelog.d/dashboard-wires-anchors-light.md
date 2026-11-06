### Fixed: dashboard source wires start at their own row and carry the travelling light
- The Sources card and the Exposure flow draw every wire with one shared component. A wire leaves from the centre of its row's name and bar (a stale note line no longer shifts it), is re-measured when a row changes height, when the data refreshes or when fonts load, and is dropped when its anchor lies outside the card.
- Healthy wires with data show a light travelling from source to target at one speed; stale, failed and empty wires stay still, and nothing moves under reduced motion.
