import stem.control

with stem.control.Controller.from_port(address='127.0.0.1', port=9051) as controller:
  controller.authenticate()

  try:
    circuit_id = input('Enter circuit id: ')
    def attach_stream(stream):
      if stream.status == 'NEW':
        controller.attach_stream(stream.id, circuit_id)

    try:
      controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)
      controller.set_conf('__LeaveStreamsUnattached', '1')  # leave stream management to us

      input('Press any key to continue...')

    finally:
      controller.remove_event_listener(attach_stream)
      controller.reset_conf('__LeaveStreamsUnattached')

  except Exception as exc:
    print('%s' % (exc))
