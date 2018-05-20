import json
import uuid
from typing import List

import celery
from celery.task import Task
from faker import Faker
from neomodel import config

import tasks
from models import *

domain = '3wiresys.com'
# ports = ['49666/TCP', '445/TCP', '135/TCP', '139/TCP', '22/TCP']
with open('ports.json') as f:
    ports = json.load(f)

with open('software_small.json') as f:
    softwares = json.load(f)

# There will be a constant number of these
num_groups = 100
num_people = 500
num_vulnerabilities = 50
num_segments = 2
num_routers = 6  # Must be >= 2
num_switches = 10

# All of these are per parent but are a random number between 0 and value provided
mad_network_modules = 3
max_interface_cards = 3
max_interfaces = 96
max_software = 20


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
# Find the first Software that is installed on more than five (5) Devices
# MATCH (s:Software)-[r:INSTALLED]->(d) WITH s, count(r) as rel_cnt WHERE rel_cnt > 5 RETURN s limit 1;

#
# Find all Vulnerabilities that are associated with more than one node
# MATCH (v:Vulnerability)<-[r:HAS_VULNERABILITY]-(d) WITH v, count(r) as rel_cnt WHERE rel_cnt > 1 RETURN v limit 1;

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

    def load(self):
        ##
        ## Pass 1
        ##
        p1_start = datetime.now()
        ## All of these can be run in parallel inside our task framework
        p1_tasks: List[Task] = []
        self.__gen_groups(p1_tasks)
        self.__gen_ports(p1_tasks)
        self.__gen_segments(p1_tasks)
        self.__gen_software(p1_tasks)
        self.__gen_vulnerabilities(p1_tasks)
        self.__gen_routers(p1_tasks)

        p1_cg = celery.group(*p1_tasks)
        p1_cg().get()
        print('Finished pass 1 [%d][%s]' % (len(p1_tasks), datetime.now() - p1_start))

        ##
        ## Pass 2
        ##

        p2_start = datetime.now()
        p2_tasks: List[Task] = []

        p2_tasks.append(tasks.routers_mesh.s())
        self.__gen_people(p2_tasks)
        self.__gen_switches(p2_tasks)

        p2_cg = celery.group(*p2_tasks)
        p2_cg().get()
        print('Finished pass 2 [%d][%s]' % (len(p2_tasks), datetime.now() - p2_start))

        ##
        ## Pass 3
        ##

        p3_start = datetime.now()
        p3_tasks: List[Task] = []

        self.__gen_network_modules(p3_tasks)

        p3_cg = celery.group(*p3_tasks)
        p3_cg().get()
        print('Finished pass 3 [%d][%s]' % (len(p3_tasks), datetime.now() - p3_start))

        ##
        ## Pass 4
        ##

        p4_start = datetime.now()
        p4_tasks: List[Task] = []

        self.__gen_interface_cards(p4_tasks)

        p4_cg = celery.group(*p4_tasks)
        p4_cg().get()
        print('Finished pass 4 [%d][%s]' % (len(p4_tasks), datetime.now() - p4_start))

        ##
        ## Pass 5
        ##

        p5_start = datetime.now()
        p5_tasks: List[Task] = []

        self.__gen_interfaces(p5_tasks)

        p5_cg = celery.group(*p5_tasks)
        p5_cg().get()
        print('Finished pass 5 [%d][%s]' % (len(p5_tasks), datetime.now() - p5_start))

        ##
        ## Pass 6
        ##

        p6_start = datetime.now()
        p6_tasks: List[Task] = []

        self.__gen_devices(p6_tasks)

        p6_cg = celery.group(*p6_tasks)
        p6_cg().get()
        print('Finished pass 6 [%d][%s]' % (len(p6_tasks), datetime.now() - p6_start))

    def __gen_devices(self, tasks_list: List[Task]) -> None:
        # has=False will only return us IFs which don't have Device relationships (which we skip in the task anyways)
        for iface in Interface.nodes.has(devices=False):
            tasks_list.append(tasks.device_generate.s(iface.uid, self.__gen_ip(), self.__gen_hostname(), max_software))

    def __gen_hostname(self) -> str:
        while True:
            hostname = '%s.%s.3wiresys.com' % (uuid.uuid4().hex[:10].upper(), self.faker.domain_word())
            if hostname not in self.hostnames:
                self.hostnames.add(hostname)
                return hostname

    def __gen_groups(self, tasks_list: List[Task]) -> None:
        for i in range(1, num_groups + 1):
            tasks_list.append(tasks.group_generate.s(i))

    def __gen_interfaces(self, tasks_list: List[Task]) -> None:
        # has=False will only return us ICs which don't have IF relationships (which we skip in the task anyways)
        for ic in InterfaceCard.nodes.has(interfaces=False):
            tasks_list.append(tasks.interface_generate.s(ic.uid, max_interfaces))

    def __gen_interface_cards(self, tasks_list: List[Task]) -> None:
        # has=False will only return us NMs which don't have IC relationships (which we skip in the task anyways)
        for nm in NetworkModule.nodes.has(interface_cards=False):
            tasks_list.append(tasks.interface_card_generate.s(nm.uid, max_interface_cards))

    def __gen_ip(self) -> str:
        while True:
            ip = self.faker.ipv4_private()
            if ip not in self.ips:
                self.ips.add(ip)
                return ip

    def __gen_network_modules(self, tasks_list: List[Task]) -> None:
        # has=False will only return us switches which don't have NM relationships (which we skip in the task anyways)
        for switch in Switch.nodes.has(network_modules=False):
            tasks_list.append(tasks.network_module_generate.s(switch.hostname, mad_network_modules))

    def __gen_people(self, tasks_list: List[Task]) -> None:
        for i in range(1, num_people + 1):
            tasks_list.append(tasks.person_generate.s(i))

    def __gen_ports(self, tasks_list: List[Task]) -> None:
        for number, detail in ports.items():
            tasks_list.append(tasks.port_generate.s(number, detail))

    def __gen_routers(self, tasks_list: List[Task]) -> None:
        for i in range(1, num_routers + 1):
            tasks_list.append(tasks.router_generate.s(i, domain))

    def __gen_segments(self, tasks_list: List[Task]) -> None:
        for i in range(1, num_segments + 1):
            tasks_list.append(tasks.segment_generate.s(i))

    def __gen_software(self, tasks_list: List[Task]) -> None:
        for name in softwares.keys():
            tasks_list.append(tasks.software_generate.s(name, softwares[name]['version']))

    def __gen_switches(self, tasks_list: List[Task]):
        for i in range(1, num_switches + 1):
            tasks_list.append(tasks.switch_generate.s(i, domain))

    def __gen_vulnerabilities(self, tasks_list: List[Task]) -> None:
        for i in range(1, num_vulnerabilities + 1):
            tasks_list.append(tasks.vulnerability_generate.s(i))


if __name__ == '__main__':
    config.DATABASE_URL = 'bolt://neo4j:123inwego@localhost:7687'
    loader = Loader()
    loader.load()
