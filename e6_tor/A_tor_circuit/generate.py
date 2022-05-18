import stem.control

with stem.control.Controller.from_port(address='127.0.0.1', port=9051) as controller:
  controller.authenticate()

  relay_fingerprints = [desc.fingerprint for desc in controller.get_network_statuses()]

  path = []
  relay_count = int(input('Enter number of relays: '))
  for i in range(relay_count):
    print('Enter fp', i + 1, ': ', end='', sep='')
    fingerprint = input()
    path.append(fingerprint)

  try:
    circuit_id = controller.new_circuit(path, await_build = True)

    print('New circuit created! Id: %s' % (circuit_id))
    print('Using circuit Id: ', controller.get_circuit(circuit_id))
  except Exception as exc:
    print('%s' % (exc))
