import json
import uuid
from random import choice
from random import randint
from typing import Dict, List, Type

from faker import Faker
from neomodel import config

from models import Device, EndUserDevice, Group, Interface, InterfaceCard, NetworkModule, Person, Port, PrinterDevice, \
    Router, Segment, Software, Switch, UnknownDevice, VoIPDevice, Vulnerability

domain = '3wiresys.com'

# There will be a constant number of these
num_groups = 100
num_people = 500
num_vulnerabilities = 5
num_segments = 2
num_routers = 5  # Must be >= 2
num_switches = 10

# All of these are per parent but are a random number between 0 and value provided
num_nms = 3
num_ics = 3
num_interfaces = 96
max_software = 20

# num_groups = 5
# num_people = 5
# num_vulnerabilities = 5
# num_segments = 1
# num_routers = 2  # Must be >= 2
# num_switches = 2
# num_nms = 1
# num_ics = 1
# num_interfaces = 4
# max_software = 3

functions = ['Laptop', 'Printer', 'VoIP']
interface_speeds = ['10/100/1000-TX', '10/100BaseTX']

ports = ['49666/TCP', '445/TCP', '135/TCP', '139/TCP', '22/TCP']

laptop_avs = ['AVG', 'McAfee', 'Norton']
with open('laptop_models.json') as f:
    laptops = json.load(f)
with open('laptop_os.json') as f:
    laptop_os = json.load(f)

with open('nic_vendors.json') as f:
    nic_vendors = json.load(f)

with open('printers.json') as f:
    printers = json.load(f)

with open('software_small.json') as f:
    softwares = json.load(f)

switch_vendors = ['Cisco']
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


#
# Find all switches that VoIP device hanging off of them
# match (device:VoIPDevice)-[*]->(switch:Switch) return switch

#
# Find the switch that has ip `192.168.9.74` hanging off of it
# match (:Device{ip: '192.168.9.74'})-[*]->(switch:Switch) return switch

#
# Find the path from the device with ip `192.168.9.74` to its Switch
# match path = (:Device{ip: '192.168.9.74'})-[*]->(:Switch) return path

#
# Find devices that were reported by X but NOT y
# match path = (:Device{reported_x: true, reported_y: false})-[*]->(s:Switch) return path

#
# Find the first Sotware that is installed on more than one Device
# MATCH (s:Software)-[r:INSTALLED]->(d) WITH s, count(r) as rel_cnt WHERE rel_cnt > 5 RETURN s limit 1;

#
# Delete all items in the database
# MATCH (n) DETACH DELETE n

# match (:Device{ip: '10.172.120.141'})<-[:UPLINK]-(interface)<-[:CONTAINS]-(subslot)<-[:CONTAINS]-(slot)
# <-[:CONTAINS]-(switch) return switch


class Loader:
    def __init__(self):
        self.faker = Faker()
        self.ips = set()
        self.hostnames = set()

        self.devices: List[Device] = []
        self.groups: List[Group] = []
        self.interface_cards: List[InterfaceCard] = []
        self.network_modules: List[NetworkModule] = []
        self.interfaces: List[Interface] = []
        self.people: List[Person] = []
        self.ports: List[Port] = []
        self.routers: List[Router] = []
        self.segments: List[Segment] = []
        self.software: List[Software] = []
        self.switches: List[Switch] = []
        self.vulnerabilities: List[Vulnerability] = []

    def load(self):
        # UPSERT a set of groups that Person's can be part of
        self.__gen_groups()

        # UPSERT a set of Persons that Devices can associate to
        self.__gen_people()

        # UPSERT a set of ports that Devices can have open (i.e., 22/TCP)
        self.__gen_ports()

        # UPSERT a set of vulnerabilities that Devices can have open
        self.__gen_vulnerabilities()

        # UPSERT a set of software that Devices can have installed
        self.__gen_software()

        # UPSERT a set of segments that Devices can be part of
        self.__gen_segments()

        # UPSERT the routers that we are going to be dealing with
        self.__gen_routers()

        # UPSERT the switches that we are going to be dealing with
        self.__gen_switches()

        # Generate the network modules within the switches (if they don't exist already)
        self.__gen_network_modules()

        # Generate the interface cards within the network modules (if they don't exist already)
        self.__gen_interface_cards()

        # Generate the interfaces within the interface cards (if they don't exist already)
        self.__gen_interfaces()

        # Generate the devices (if they don't exist already)
        self.__gen_devices()

    def __gen_devices(self) -> None:
        print('\n\nDEVICES Starting')
        for interface in self.interfaces:
            sw_hostname = interface.interface_card.get().network_module.get().switch.get().hostname
            nm_position = interface.interface_card.get().network_module.get().position
            ic_position = interface.interface_card.get().position
            pt_position = interface.position

            if len(interface.devices.all()):
                print('\tUsing existing Device for %s:%d\%d\%d' % (sw_hostname, nm_position, ic_position, pt_position))
            else:
                print('\tCreating new Device for %s:%d\%d\%d' % (sw_hostname, nm_position, ic_position, pt_position))
                func = self.faker.word(ext_word_list=functions)
                if func == 'Laptop':
                    self.devices.append(self.__gen_device_laptop(interface))
                elif func == 'Printer':
                    self.devices.append(self.__gen_device_printer(interface))
                elif func == 'VoIP':
                    self.devices.append(self.__gen_device_voip(interface))
                else:
                    self.devices.append(self.__gen_device_generic(interface, func))
        print('DEVICES Finished')

    def __gen_device_base(self, interface: Interface, device_class: Type[Device], device_data: Dict,
                          base_data: Dict = None) -> Device:
        if not base_data:
            base_data = self.__gen_device_base_data()

        # noinspection PyTypeChecker
        device = device_class.create_or_update({**base_data, **device_data}, relationship=interface.devices)[0]
        print('\t\tUpserted Device %s - %s' % (device.function, device.hostname))

        # Give the device to any segment
        if not len(device.segment.all()):
            device_seg = choice(self.segments)
            device.segment.connect(device_seg)
            print('\t\tConnected segment -> %s' % device_seg.name)

        # Set a few open ports
        if not len(device.open_ports.all()):
            for i in range(0, 3):
                device.open_ports.connect(choice(self.ports))

        return device

    def __gen_device_base_data(self) -> Dict:
        return {
            'ip': self.__gen_ip(),
            'mac_address': self.faker.mac_address(),
            'hostname': self.__gen_hostname(),
            'reported_x': self.faker.boolean(),
            'reported_y': self.faker.boolean(),
            'reported_z': self.faker.boolean(),
            'hw_model': None,
            'hw_vendor': None,
            'linux_secure_connector': False,
            'linux_ssh': False,
            'mac_ssh': False,
            'netbios_domain': None,
            'netbios_hostname': None,
            'network_function': None,
            'nic_vendor': choice(nic_vendors),
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

    def __gen_device_generic(self, interface: Interface, func: str) -> Device:
        device_data = {
            'function': func
        }

        return self.__gen_device_base(interface, UnknownDevice, device_data)

    def __gen_device_laptop(self, interface: Interface) -> Device:
        laptop_vendor = choice(list(laptops.keys()))
        laptop_model = choice(laptops[laptop_vendor])

        base_data = self.__gen_device_base_data()
        hostname_parts = base_data['hostname'].split('.')

        av_installed = self.faker.boolean()
        laptop_data = {
            'user_name': self.faker.user_name(),
            'function': 'Laptop',
            'hw_model': laptop_model,
            'hw_vendor': laptop_vendor,
            'netbios_domain': hostname_parts[1],
            'netbios_hostname': hostname_parts[0],
            'network_function': 'Windows Machine',
            'num_hosts_on_port': 1,
            'os': 'Windows',
            'os_fingerprint': choice(laptop_os),
            'win_av_installed': av_installed,
            'win_av_program': choice(laptop_avs) if av_installed else None,
            'win_av_running': self.faker.boolean(),
            'win_av_update_last': self.faker.past_datetime() if av_installed else None,
            'win_manageable_deployment_type': 'Permanent As Service ',
            'win_manageable_by_domain': True,
            'win_manageable_secure': True,
            'win_secure_systray': True,
            'win_secure_version': '10.7.01.0046 (x64)'
        }

        laptop: EndUserDevice = self.__gen_device_base(interface, EndUserDevice, laptop_data, base_data)

        # Set a few open vulnerabilities
        if not len(laptop.vulnerabilities.all()):
            for i in range(0, randint(0, 3)):
                vulnerability = choice(self.vulnerabilities)
                laptop.vulnerabilities.connect(vulnerability)
                print('\t\tConnected vulnerability -> %s' % vulnerability.name)

        # Set a few software associations
        if not len(laptop.software.all()):
            for i in range(0, randint(0, max_software)):
                software = choice(self.software)
                laptop.software.connect(software)
                print('\t\tConnected software -> %s' % software.name)

        # Assign to a user
        if not len(laptop.user.all()):
            if len(self.people):
                person = self.people.pop()
                laptop.user.connect(person)
                print('\t\tConnected person -> %s' % person.name_display)
            else:
                print('\t\tNo connected person (exhausted list)')

        return laptop

    def __gen_device_printer(self, interface: Interface) -> Device:
        printer_vendor = choice(list(printers.keys()))
        printer_model = choice(printers[printer_vendor])

        base_data = self.__gen_device_base_data()

        printer_data = {
            'hw_model': printer_model,
            'hw_vendor': printer_vendor,
            'network_function': 'Printer',
        }

        return self.__gen_device_base(interface, PrinterDevice, printer_data, base_data)

    def __gen_device_voip(self, interface: Interface) -> Device:
        voip_vendor = choice(list(voips.keys()))
        voip_model = choice(voips[voip_vendor])

        base_data = self.__gen_device_base_data()

        voip_data = {
            'hw_model': voip_model,
            'hw_vendor': voip_vendor,
            'network_function': 'VoIP',
        }

        return self.__gen_device_base(interface, VoIPDevice, voip_data, base_data)

    def __gen_groups(self) -> None:
        print('\n\nGROUPS Starting')

        for i in range(1, num_groups + 1):
            # noinspection PyTypeChecker
            group = Group.create_or_update({'name': 'group_%s' % i})[0]
            self.groups.append(group)
            print('\t%s: Upserted' % group.name)

        print('GROUPS Finished')

    def __gen_hostname(self) -> str:
        while True:
            hostname = '%s.%s.3wiresys.com' % (uuid.uuid4().hex[:10].upper(), self.faker.domain_word())
            if hostname not in self.hostnames:
                self.hostnames.add(hostname)
                return hostname

    def __gen_interfaces(self) -> None:
        print('\n\nINTERFACES Starting')
        for ic in self.interface_cards:
            switch = ic.network_module.get().switch.get()
            nm_position = ic.network_module.get().position
            ic_position = ic.position
            if len(ic.interfaces.all()):
                print('\tUsing existing Interface(s) for %s:%d\%d' % (switch.hostname, nm_position, ic_position))
                self.interfaces.extend(ic.interfaces.all())
            else:
                print('\tCreating new Interface(s) for %s:%d\%d' % (switch.hostname, nm_position, ic_position))
                for position in range(0, randint(1, num_interfaces)):
                    # noinspection PyTypeChecker
                    interface = Interface.create_or_update({'position': position}, relationship=ic.interfaces)[0]
                    print('\t\tUpserted Interface %s:%d\%d\%d' % (
                        switch.hostname, nm_position, ic_position, interface.position))
                    self.interfaces.append(interface)
        print('INTERFACES Finished')

    def __gen_interface_cards(self) -> None:
        print('\n\nINTERFACE CARDS Starting')

        for nm in self.network_modules:
            switch = nm.switch.get()
            if len(nm.interface_cards.all()):
                print('\tUsing existing InterfaceCard(s) for %s:%d' % (switch.hostname, nm.position))
                self.interface_cards.extend(nm.interface_cards.all())
            else:
                print('\tCreating new InterfaceCard(s) for %s:%d' % (switch.hostname, nm.position))
                for position in range(0, randint(1, num_ics)):
                    card = self.faker.word(ext_word_list=switch_interface_cards)
                    data = {
                        'position': position,
                        'type': card['type'],
                        'model': card['model'],
                        'serial_no': self.faker.isbn10()
                    }
                    # noinspection PyTypeChecker
                    ic = InterfaceCard.create_or_update(data, relationship=nm.interface_cards)[0]
                    print('\t\tUpserted InterfaceCard %s:%d\%d' % (switch.hostname, nm.position, ic.position))
                    self.interface_cards.append(ic)
        print('INTERFACE CARDS Finished')

    def __gen_ip(self) -> str:
        while True:
            ip = self.faker.ipv4_private()
            if ip not in self.ips:
                self.ips.add(ip)
                return ip

    def __gen_network_modules(self) -> None:
        print('\n\nNETWORK MODULES Starting')
        for switch in self.switches:
            if len(switch.network_modules.all()):
                print('\tUsing existing NetworkModule(s) for %s' % switch.hostname)
                self.network_modules.extend(switch.network_modules.all())
            else:
                print('\tCreating new NetworkModule(s) for %s' % switch.hostname)
                for position in range(0, randint(1, num_nms)):
                    module = self.faker.word(ext_word_list=switch_network_modules)
                    data = {
                        'position': position,
                        'type': module['type'],
                        'model': module['model'],
                        'serial_no': self.faker.isbn10()
                    }
                    # noinspection PyTypeChecker
                    nm = NetworkModule.create_or_update(data, relationship=switch.network_modules)[0]
                    print('\t\tUpserted NetworkModule %s:%d' % (switch.hostname, nm.position))
                    self.network_modules.append(nm)
        print('NETWORK MODULES Finished')

    def __gen_people(self) -> None:
        print('\n\nPEOPLE Starting')

        for i in range(1, num_people + 1):
            name = self.faker.name()
            data = {
                'user_name': self.faker.user_name(),
                'account_disabled': self.faker.boolean(),
                'account_expired': self.faker.boolean(),
                'company': self.faker.company(),
                'department': self.faker.word(),
                'email': self.faker.email(),
                'name_display': name,
                'name_family': name.split(' ')[1],
                'name_given': name.split(' ')[0],
                'password_last_set': self.faker.past_datetime(),
                'phone': self.faker.phone_number(),
                'title': self.faker.job(),
            }
            # noinspection PyTypeChecker
            person = Person.create_or_update(data)[0]
            self.people.append(person)
            print('\t%s: Upserted' % person.name_display)

            # Set a few groups
            if not len(person.groups.all()):
                for j in range(0, randint(0, 10)):
                    group = choice(self.groups)
                    person.groups.connect(group)
                    print('\t\tConnected group -> %s' % group.name)

        print('PEOPLE Finished')

    def __gen_ports(self) -> None:
        print('\n\nPORTS Starting')
        for port in ports:
            # noinspection PyTypeChecker
            port = Port.create_or_update({'name': port})[0]
            self.ports.append(port)
            print('\t%s: Upserted' % port.name)
        print('PORTS Finished')

    def __gen_routers(self) -> None:
        print('\n\nROUTERS Starting')
        for router_i in range(1, num_routers + 1):
            hostname = 'core%d.%s' % (router_i, domain)
            ip = '10.0.0.%d' % router_i
            mac_address = self.faker.mac_address(),

            # noinspection PyTypeChecker
            router = Router.create_or_update({'ip': ip, 'hostname': hostname, 'mac_address': mac_address})[0]
            self.routers.append(router)
            print('\t%s: Upserted' % router.hostname)

            for router_other in self.routers:
                if router != router_other:
                    if not router.peers.is_connected(router_other):
                        print('\t\t%s: connection created -> %s' % (router.hostname, router_other.hostname))
                        router.peers.connect(router_other)
                    else:
                        print('\t\t%s: connection existed -> %s' % (router.hostname, router_other.hostname))
        print('ROUTERS Finished')

    def __gen_segments(self) -> None:
        print('\n\nSEGMENTS Starting')
        for segment_i in range(1, num_segments + 1):
            # noinspection PyTypeChecker
            segment = Segment.create_or_update({'name': 'segment_%s' % segment_i})[0]
            self.segments.append(segment)
            print('\t%s: Upserted' % segment.name)
        print('SEGMENTS Finished')

    def __gen_software(self) -> None:
        print('\n\nSOFTWARE Starting')
        for software_name in softwares.keys():
            data = {'name': software_name, 'version': softwares[software_name]['version']}
            # noinspection PyTypeChecker
            sware = Software.create_or_update(data)[0]
            self.software.append(sware)
            print('\t%s: Upserted' % sware.name)
        print('SOFTWARE Finished')

    def __gen_switches(self):
        print('\n\nSWITCHES Starting')
        for switch_i in range(1, num_switches + 1):
            hostname = 'edge%d.%s' % (switch_i, domain)
            vendor = self.faker.word(ext_word_list=switch_vendors)
            model = self.faker.word(ext_word_list=switch_models)

            switch_properties = {
                'ip': '10.0.%d.1' % switch_i,
                'mac_address': self.faker.mac_address(),
                'hostname': hostname,
                'vendor': vendor,
                'model': model,
                'version': self.faker.word(ext_word_list=switch_versions)
            }
            # noinspection PyTypeChecker
            switch = Switch.create_or_update(switch_properties)[0]
            print('\t%s: Upserted' % switch.hostname)
            self.switches.append(switch)

            #
            # Make sure the switch has uplinks
            while len(switch.routers.all()) < 2:
                uplink_router = choice(self.routers)
                switch.routers.connect(uplink_router)
                switch.refresh()
                print('\t\tuplink created -> %s' % uplink_router.hostname)

        print('SWITCHES Finished')

    def __gen_vulnerabilities(self) -> None:
        print('\n\nVULNERABILITIES Starting')
        for vuln_i in range(1, num_vulnerabilities + 1):
            # noinspection PyTypeChecker
            vulnerability = Vulnerability.create_or_update({'name': 'vulnerability_%s' % vuln_i})[0]
            self.vulnerabilities.append(vulnerability)
            print('\t%s: Upserted' % vulnerability.name)
        print('VULNERABILITIES Finished')


if __name__ == '__main__':
    config.DATABASE_URL = 'bolt://neo4j:123inwego@localhost:7687'
    loader = Loader()
    loader.load()
