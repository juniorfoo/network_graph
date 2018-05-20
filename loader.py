import json
import uuid
from random import choice
from random import randint
from typing import Dict, List, Type

from faker import Faker
from neomodel import config

from models import Device, EndUserDevice, Interface, InterfaceCard, NetworkModule, Port, Router, Segment, Switch, \
    UnknownDevice, Vulnerability

domain = '3wiresys.com'

## There will be a constant number of these
# num_vulnerabilities = 5
# num_segments = 2
# num_routers = 5  # Must be >= 2
# num_switches = 10
#
# # All of these are per parent but are a random number between 0 and value provided
# num_nms = 3
# num_ics = 3
# num_interfaces = 96

## There will be a constant number of these
num_vulnerabilities = 5
num_segments = 1
num_routers = 2  # Must be >= 2
num_switches = 2

# All of these are per parent but are a random number between 0 and value provided
num_nms = 1
num_ics = 1
num_interfaces = 4

functions = ['Laptop', 'Printer', 'Server', 'VoIP']
interface_speeds = ['10/100/1000-TX', '10/100BaseTX']
ports = ['49666/TCP', '445/TCP', '135/TCP', '139/TCP', '22/TCP']
vendors = ['Cisco']

with open('switch_models.json') as f:
    switch_models = json.load(f)
with open('switch_versions.json') as f:
    switch_versions = json.load(f)
with open('switch_network_modules.json') as f:
    switch_network_modules = json.load(f)
with open('switch_interface_cards.json') as f:
    switch_interface_cards = json.load(f)


# match (device:Device{function:'VoIP'})<-[*]-(switch) return switch
# match (:Device{ip: '10.172.120.141'})<-[*]-(switch) return switch
# match (:Device{ip: '10.172.120.141'})<-[*]-(switch:Switch) return switch
# match (:Device{ip: '10.172.120.141'})<-[:UPLINK]-(interface)<-[:CONTAINS]-(subslot)<-[:CONTAINS]-(slot)<-[:CONTAINS]-(switch) return switch
# MATCH (n) DETACH DELETE n


class Loader:
    def __init__(self):
        self.faker = Faker()
        self.ips = set()
        self.hostnames = set()

        self.devices: List[Device] = []
        self.interface_cards: List[InterfaceCard] = []
        self.network_modules: List[NetworkModule] = []
        self.interfaces: List[Interface] = []
        self.ports: List[Port] = []
        self.routers: List[Router] = []
        self.segments: List[Segment] = []
        self.switches: List[Switch] = []
        self.vulnerabilities: List[Vulnerability] = []

    def load(self):
        self.__gen_ports()

        self.__gen_vulnerabilities()

        self.__gen_segments()

        self.__gen_routers()

        self.__gen_switches()

        self.__gen_network_modules()

        self.__gen_interface_cards()

        self.__gen_interfaces()

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
                function = self.faker.word(ext_word_list=functions)
                # functions = ['Laptop', 'Printer', 'Server', 'Unknown', 'VoIP']
                if function == 'Laptop':
                    self.devices.append(self.__gen_device_laptop(interface))
                else:
                    self.devices.append(self.__gen_device_generic(interface, function))
        print('DEVICES Finished')

    def __gen_device_base(self, interface: Interface, device_class: Type[Device], device_data: Dict) -> Device:
        base_data = {
            'ip': self.__gen_ip(),
            'mac_address': self.faker.mac_address(),
            'hostname': self.__gen_hostname(),
        }
        # noinspection PyTypeChecker
        device = device_class.create_or_update({**base_data, **device_data}, relationship=interface.devices)[0]
        print('\t\tUpserted Device %s' % device.hostname)

        # Give the device to any segment
        if not len(device.segment.all()):
            device_seg = choice(self.segments)
            device.segment.connect(device_seg)
            print('\t\tConnected segment -> %s' % device_seg.name)

        # Set a few open ports
        if not len(device.open_ports.all()):
            for i in range(0, 3):
                device.open_ports.connect(choice(self.ports))

        # Set a few open vulnerabilities
        if not len(device.vulnerabilities.all()):
            for i in range(0, 3):
                device.vulnerabilities.connect(choice(self.vulnerabilities))

        return device

    def __gen_device_generic(self, interface: Interface, function: str) -> Device:
        device_data = {
            'function': function
        }

        return self.__gen_device_base(interface, EndUserDevice, device_data)

    def __gen_device_laptop(self, interface: Interface) -> Device:
        device_data = {
            'user_name': self.faker.user_name(),
            'function': 'Laptop'
        }

        return self.__gen_device_base(interface, UnknownDevice, device_data)

    def __gen_hostname(self) -> str:
        while True:
            hostname = '%s.3wiresys.com' % uuid.uuid4().hex[:10].upper()
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
            segment = Segment.create_or_update({'name': 'segment%s' % segment_i})[0]
            self.segments.append(segment)
            print('\t%s: Upserted' % segment.name)
        print('SEGMENTS Finished')

    def __gen_switches(self):
        print('\n\nSWITCHES Starting')
        for switch_i in range(1, num_switches + 1):
            hostname = 'edge%d.%s' % (switch_i, domain)
            vendor = self.faker.word(ext_word_list=vendors)
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
