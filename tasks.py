import json
import random
from typing import Dict, List, Type

from celery import Celery
from faker import Faker
from neomodel import config

from models import Device, EndUserDevice, Group, Interface, InterfaceCard, NetworkModule, Person, Port, PrinterDevice, \
    Router, Segment, Software, Switch, UnknownDevice, VoIPDevice, Vulnerability

app = Celery('tasks', broker='redis://localhost', backend='redis://localhost')
app.conf.update(
    task_serializer='json',
    accept_content=['json'],  # Ignore other content
    result_serializer='json',
    timezone='America/Denver',
    enable_utc=True,
)
faker = Faker()

config.DATABASE_URL = 'bolt://neo4j:123inwego@localhost:7687'

functions = ['Laptop', 'Printer', 'VoIP']
interface_speeds = ['10/100/1000-TX', '10/100BaseTX']
laptop_avs = ['AVG', 'McAfee', 'Norton']
switch_vendors = ['Cisco']

with open('laptop_models.json') as f:
    laptops = json.load(f)
with open('laptop_os.json') as f:
    laptop_os = json.load(f)
with open('nic_vendors.json') as f:
    nic_vendors = json.load(f)
with open('printers.json') as f:
    printers = json.load(f)
with open('switch_models.json') as f:
    switch_models = json.load(f)
with open('switch_versions.json') as f:
    switch_versions = json.load(f)
with open('switch_network_modules.json') as f:
    switch_network_modules = json.load(f)
with open('switch_interface_cards.json') as f:
    switch_interface_cards = json.load(f)
with open('voip_models.json') as f:
    voips = json.load(f)


# @app.task(max_retries=10, retry_backoff=True, autoretry_for=(ConstraintValidationFailed,))
@app.task
def device_generate(interface_uid: str, ip: str, hostname: str, max_software: int) -> None:
    iface = Interface.nodes.get(uid=interface_uid)

    sw_hostname = iface.interface_card.get().network_module.get().switch.get().hostname
    nm_position = iface.interface_card.get().network_module.get().position
    ic_position = iface.interface_card.get().position
    pt_position = iface.position

    if len(iface.devices.all()):
        print('\tUsing existing Device for %s:%d\%d\%d' % (sw_hostname, nm_position, ic_position, pt_position))
    else:
        print('\tCreating new Device for %s:%d\%d\%d' % (sw_hostname, nm_position, ic_position, pt_position))
        func = faker.word(ext_word_list=functions)
        if func == 'Laptop':
            __gen_device_laptop(iface, ip, hostname, max_software)
        elif func == 'Printer':
            __gen_device_printer(iface, ip, hostname)
        elif func == 'VoIP':
            __gen_device_voip(iface, ip, hostname)
        else:
            __gen_device_generic(iface, func, ip, hostname)


@app.task
def group_generate(index) -> None:
    # noinspection PyTypeChecker
    group = Group.create_or_update({'name': 'group_%s' % index})[0]
    print('\t%s: Upserted' % group.name)


@app.task
def interface_card_generate(network_module_uid: str, max_cards: int) -> None:
    nm = NetworkModule.nodes.get(uid=network_module_uid)
    switch = nm.switch.get()

    if len(nm.interface_cards.all()):
        print('\tUsing existing InterfaceCard(s) for %s:%d' % (switch.hostname, nm.position))
    else:
        print('\tCreating new InterfaceCard(s) for %s:%d' % (switch.hostname, nm.position))
        for position in range(0, random.randint(1, max_cards)):
            card = faker.word(ext_word_list=switch_interface_cards)
            data = {
                'position': position,
                'type': card['type'],
                'model': card['model'],
                'serial_no': faker.isbn10()
            }
            # noinspection PyTypeChecker
            ic = InterfaceCard.create_or_update(data, relationship=nm.interface_cards)[0]
            print('\t\tUpserted InterfaceCard %s:%d\%d' % (switch.hostname, nm.position, ic.position))


@app.task
def interface_generate(interface_card_uid: str, max_interfaces: int) -> None:
    ic = InterfaceCard.nodes.get(uid=interface_card_uid)
    nm = ic.network_module.get()
    switch = nm.switch.get()

    if len(ic.interfaces.all()):
        print('\tUsing existing Interface(s) for %s:%d\%d' % (switch.hostname, nm.position, ic.position))
    else:
        print('\tCreating new Interface(s) for %s:%d\%d' % (switch.hostname, nm.position, ic.position))
        for position in range(0, random.randint(1, max_interfaces)):
            # noinspection PyTypeChecker
            interface = Interface.create_or_update({'position': position}, relationship=ic.interfaces)[0]
            print('\t\tUpserted Interface %s:%d\%d\%d' % (
                switch.hostname, nm.position, ic.position, interface.position))


@app.task
def network_module_generate(switch_hostname: str, max_modules: int) -> None:
    switch = Switch.nodes.get(hostname=switch_hostname)

    if len(switch.network_modules.all()):
        print('\tUsing existing NetworkModule(s) for %s' % switch.hostname)
    else:
        print('\tCreating new NetworkModule(s) for %s' % switch.hostname)
        for position in range(0, random.randint(1, max_modules)):
            module = faker.word(ext_word_list=switch_network_modules)
            data = {
                'position': position,
                'type': module['type'],
                'model': module['model'],
                'serial_no': faker.isbn10()
            }
            # noinspection PyTypeChecker
            nm = NetworkModule.create_or_update(data, relationship=switch.network_modules)[0]
            print('\t\tUpserted NetworkModule %s:%d' % (switch.hostname, nm.position))


@app.task
def person_generate(index: int) -> None:
    groups = Group.nodes.all()
    name = faker.name()
    data = {
        'user_name': faker.user_name(),
        'account_disabled': faker.boolean(),
        'account_expired': faker.boolean(),
        'company': faker.company(),
        'department': faker.word(),
        'email': faker.email(),
        'name_display': name,
        'name_family': name.split(' ')[1],
        'name_given': name.split(' ')[0],
        'password_last_set': faker.past_datetime(),
        'phone': faker.phone_number(),
        'title': faker.job(),
    }
    # noinspection PyTypeChecker
    person = Person.create_or_update(data)[0]
    print('\t%s: Upserted' % person.name_display)

    # Set a few groups
    if not len(person.groups.all()):
        for j in range(0, random.randint(0, 10)):
            group = random.choice(groups)
            person.groups.connect(group)
            print('\t\tConnected group -> %s' % group.name)


@app.task
def port_generate(number: str, detail: Dict) -> None:
    # noinspection PyTypeChecker
    port = Port.create_or_update({'number': number, 'details': detail})[0]
    print('\t%s: Upserted' % port.number)


@app.task
def router_generate(index: int, domain: str) -> None:
    hostname = 'core%d.%s' % (index, domain)
    ip = '10.0.0.%d' % index
    mac_address = faker.mac_address(),

    # noinspection PyTypeChecker
    router = Router.create_or_update({'ip': ip, 'hostname': hostname, 'mac_address': mac_address})[0]
    print('\t%s: Upserted' % router.hostname)


@app.task
def routers_mesh() -> None:
    routers: List[Router] = Router.nodes.all()
    while len(routers):
        router = routers.pop()

        for router_other in routers:
            if router != router_other:
                if not router.peers.is_connected(router_other):
                    print('\t\t%s: connection created -> %s' % (router.hostname, router_other.hostname))
                    router.peers.connect(router_other)
                else:
                    print('\t\t%s: connection existed -> %s' % (router.hostname, router_other.hostname))


@app.task
def segment_generate(index: int) -> None:
    # noinspection PyTypeChecker
    segment = Segment.create_or_update({'name': 'segment_%s' % index})[0]
    print('\t%s: Upserted' % segment.name)


@app.task
def software_generate(name: str, version: str) -> None:
    data = {'name': name, 'version': version}
    # noinspection PyTypeChecker
    software = Software.create_or_update(data)[0]
    print('\t%s: Upserted' % software.name)


@app.task
def switch_generate(index: int, domain: str) -> None:
    hostname = 'edge%d.%s' % (index, domain)
    vendor = faker.word(ext_word_list=switch_vendors)
    model = faker.word(ext_word_list=switch_models)

    switch_properties = {
        'ip': '10.0.%d.1' % index,
        'mac_address': faker.mac_address(),
        'hostname': hostname,
        'vendor': vendor,
        'model': model,
        'version': faker.word(ext_word_list=switch_versions)
    }
    # noinspection PyTypeChecker
    switch = Switch.create_or_update(switch_properties)[0]
    print('\t%s: Upserted' % switch.hostname)

    #
    # Make sure the switch has uplinks
    if len(switch.routers.all()) < 2:
        routers = Router.nodes.all()

        while len(switch.routers.all()) < 2:
            uplink_router = random.choice(routers)
            switch.routers.connect(uplink_router)
            switch.refresh()
            print('\t\tuplink created -> %s' % uplink_router.hostname)


@app.task
def vulnerability_generate(index: int) -> None:
    # noinspection PyTypeChecker
    vulnerability = Vulnerability.create_or_update({'name': 'vulnerability_%s' % index})[0]
    print('\t%s: Upserted' % vulnerability.name)


def __gen_device_base(interface: Interface, device_class: Type[Device], device_data: Dict, base_data: Dict) -> Device:
    # noinspection PyTypeChecker
    device = device_class.create_or_update({**base_data, **device_data}, relationship=interface.devices)[0]
    print('\t\tUpserted Device %s - %s' % (device.function, device.hostname))

    # Give the device to any segment
    if not len(device.segment.all()):
        device_seg = random.choice(Segment.nodes.all())
        device.segment.connect(device_seg)
        print('\t\tConnected segment -> %s' % device_seg.name)

    # Set a few open ports
    if not len(device.open_ports.all()):
        ports = Port.nodes.all()
        for i in range(0, 3):
            device.open_ports.connect(random.choice(ports))

    return device


def __gen_device_base_data(ip: str, hostname: str) -> Dict:
    return {
        'ip': ip,
        'mac_address': faker.mac_address(),
        'hostname': hostname,
        'reported_x': faker.boolean(),
        'reported_y': faker.boolean(),
        'reported_z': faker.boolean(),
        'hw_model': None,
        'hw_vendor': None,
        'linux_secure_connector': False,
        'linux_ssh': False,
        'mac_ssh': False,
        'netbios_domain': None,
        'netbios_hostname': None,
        'network_function': None,
        'nic_vendor': random.choice(nic_vendors),
        'num_hosts_on_port': 0,
        'os': None,
        'os_fingerprint': None,
        'win_av_installed': False,
        'win_av_program': None,
        'win_av_running': False,
        'win_av_update_last': None,
        'win_manageable_deployment_type': None,
        'win_manageable_by_domain': False,
        'win_manageable_secure': False,
        'win_secure_systray': False,
        'win_secure_version': None
    }


def __gen_device_generic(interface: Interface, ip: str, hostname: str, func: str) -> Device:
    base_data = __gen_device_base_data(ip, hostname)
    device_data = {
        'function': func
    }

    return __gen_device_base(interface, UnknownDevice, base_data, device_data)


def __gen_device_laptop(interface: Interface, ip: str, hostname: str, max_software: int) -> Device:
    laptop_vendor = random.choice(list(laptops.keys()))
    laptop_model = random.choice(laptops[laptop_vendor])

    base_data = __gen_device_base_data(ip, hostname)
    hostname_parts = base_data['hostname'].split('.')

    av_installed = faker.boolean()
    laptop_data = {
        'user_name': faker.user_name(),
        'function': 'Laptop',
        'hw_model': laptop_model,
        'hw_vendor': laptop_vendor,
        'netbios_domain': hostname_parts[1],
        'netbios_hostname': hostname_parts[0],
        'network_function': 'Windows Machine',
        'num_hosts_on_port': 1,
        'os': 'Windows',
        'os_fingerprint': random.choice(laptop_os),
        'win_av_installed': av_installed,
        'win_av_program': random.choice(laptop_avs) if av_installed else None,
        'win_av_running': faker.boolean(),
        'win_av_update_last': faker.past_datetime() if av_installed else None,
        'win_manageable_deployment_type': 'Permanent As Service ',
        'win_manageable_by_domain': True,
        'win_manageable_secure': True,
        'win_secure_systray': True,
        'win_secure_version': '10.7.01.0046 (x64)'
    }

    laptop: EndUserDevice = __gen_device_base(interface, EndUserDevice, base_data, laptop_data)

    # Set a few open vulnerabilities
    if not len(laptop.vulnerabilities.all()):
        vulnerabilities = Vulnerability.nodes.all()
        for i in range(0, random.randint(0, 3)):
            vulnerability = random.choice(vulnerabilities)
            laptop.vulnerabilities.connect(vulnerability)
            print('\t\tConnected vulnerability -> %s' % vulnerability.name)

    # Set a few software associations
    if not len(laptop.software.all()):
        softwares = Software.nodes.all()
        for i in range(0, random.randint(0, max_software)):
            software = random.choice(softwares)
            laptop.software.connect(software)
            print('\t\tConnected software -> %s' % software.name)

    # Assign to a user
    if not len(laptop.user.all()):
        person = random.choice(Person.nodes.all())
        laptop.user.connect(person)
        print('\t\tConnected person -> %s' % person.name_display)

    return laptop


def __gen_device_printer(interface: Interface, ip: str, hostname: str) -> Device:
    printer_vendor = random.choice(list(printers.keys()))
    printer_model = random.choice(printers[printer_vendor])

    base_data = __gen_device_base_data(ip, hostname)

    printer_data = {
        'hw_model': printer_model,
        'hw_vendor': printer_vendor,
        'network_function': 'Printer',
    }

    return __gen_device_base(interface, PrinterDevice, base_data, printer_data)


def __gen_device_voip(interface: Interface, ip: str, hostname: str) -> Device:
    voip_vendor = random.choice(list(voips.keys()))
    voip_model = random.choice(voips[voip_vendor])

    base_data = __gen_device_base_data(ip, hostname)

    voip_data = {
        'hw_model': voip_model,
        'hw_vendor': voip_vendor,
        'network_function': 'VoIP',
    }

    return __gen_device_base(interface, VoIPDevice, base_data, voip_data)
