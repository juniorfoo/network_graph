from datetime import datetime

import pytz
from neomodel import BooleanProperty, DateTimeProperty, IntegerProperty, JSONProperty, Relationship, RelationshipFrom, \
    RelationshipTo, StringProperty, StructuredNode, StructuredRel, UniqueIdProperty


##
## Mixins
##

class IpMixin(object):
    hostname = UniqueIdProperty()
    ip = StringProperty(unique_index=True)
    mac_address = StringProperty()


class PluggableMixin(object):
    uid = UniqueIdProperty()
    position = IntegerProperty(required=True)
    type = StringProperty()
    model = StringProperty()
    serial_no = StringProperty()


##
## Relationships
##
class BackboneRelationship(StructuredRel):
    since = DateTimeProperty(
        default=lambda: datetime.now(pytz.utc)
    )


##
## Nodes
##

class NetworkingDevice(StructuredNode, IpMixin):
    __abstract_node__ = True

    # Properties
    type = StringProperty(required=True)
    vendor = StringProperty()
    model = StringProperty()
    version = StringProperty()
    mgmt_group = StringProperty()

    # Relationships
    # None

    # Methods
    # None


class Router(NetworkingDevice):
    # Properties
    type = StringProperty(default='Router')

    # Relationships
    peers = Relationship('Router', 'BACKBONE', model=BackboneRelationship)
    switches = RelationshipFrom('Switch', 'ROUTER_FOR')

    # Methods
    # None


class Switch(NetworkingDevice):
    # Properties
    type = StringProperty(default='Switch')

    # Relationships
    routers = RelationshipTo('Router', 'ROUTER_FOR')
    network_modules = RelationshipFrom('NetworkModule', 'CONTAINED_IN')

    # Methods
    # None


class NetworkModule(StructuredNode, PluggableMixin):
    # Properties
    # None

    # Relationships
    switch = RelationshipTo('Switch', 'CONTAINED_IN')
    interface_cards = RelationshipFrom('InterfaceCard', 'CONTAINED_IN')

    # Methods
    # None


class InterfaceCard(StructuredNode, PluggableMixin):
    # Properties
    # None

    # Relationships
    network_module = RelationshipTo('NetworkModule', 'CONTAINED_IN')
    interfaces = RelationshipFrom('Interface', 'CONTAINED_IN')

    # Methods
    # None


class Interface(StructuredNode, PluggableMixin):
    # Properties
    # None

    # Relationships
    interface_card = RelationshipTo('InterfaceCard', 'CONTAINED_IN')
    devices = RelationshipFrom('Device', 'PHYSICAL_UPLINK')

    # Methods
    # None


class Device(StructuredNode, IpMixin):
    # If I put these in place, as the doc says to, then I run into all kinds of issues
    # __abstract_node__ = True
    # __label__ = "Device"

    #
    # Properties
    function = StringProperty()
    reported_x = BooleanProperty(default=False)
    reported_y = BooleanProperty(default=False)
    reported_z = BooleanProperty(default=False)

    hw_model = StringProperty()
    hw_vendor = StringProperty()
    linux_secure_connector = BooleanProperty()
    linux_ssh = BooleanProperty()
    mac_ssh = BooleanProperty()
    mgmt_group = StringProperty()
    netbios_domain = StringProperty()
    netbios_hostname = StringProperty()
    network_function = StringProperty()
    nic_vendor = StringProperty()
    num_hosts_on_port = IntegerProperty()
    os = StringProperty()
    os_fingerprint = StringProperty()
    win_av_installed = BooleanProperty()
    win_av_program = StringProperty()
    win_av_running = BooleanProperty()
    win_av_update_last = DateTimeProperty()
    win_manageable_deployment_type = StringProperty()
    win_manageable_by_domain = BooleanProperty()
    win_manageable_secure = BooleanProperty()
    win_secure_systray = BooleanProperty()
    win_secure_version = StringProperty()

    # Relationships
    interface = RelationshipTo('Interface', 'PHYSICAL_UPLINK')
    open_ports = RelationshipTo('Port', 'USES_PORT')
    segment = RelationshipTo('Segment', 'SEGMENT')
    vulnerabilities = RelationshipTo('Vulnerability', 'HAS_VULNERABILITY')
    user = RelationshipFrom('Person', 'USES')

    # Methods
    # None


class EndUserDevice(Device):
    # Properties
    user_name = StringProperty()
    function = StringProperty(default='End-User')

    # Relationships
    software = RelationshipFrom('Software', 'INSTALLED')

    # Methods
    # None


class PrinterDevice(Device):
    # Properties
    user_name = StringProperty()
    function = StringProperty(default='Printer')

    # Relationships
    # None

    # Methods
    # None


class VoIPDevice(Device):
    # Properties
    user_name = StringProperty()
    function = StringProperty(default='VoIP')

    # Relationships
    # None

    # Methods
    # None


class UnknownDevice(Device):
    # Properties
    function = StringProperty(default='Unknown')

    # Relationships
    # None

    # Methods
    # None


class Segment(StructuredNode):
    # Properties
    name = StringProperty(unique_index=True)

    # Relationships
    device = RelationshipFrom('Device', 'SEGMENT')

    # Methods
    # None


class Software(StructuredNode):
    # Properties
    name = StringProperty(unique_index=True)
    version = StringProperty()

    # Relationships
    device = RelationshipTo('EndUserDevice', 'INSTALLED')

    # Methods
    # None


class Port(StructuredNode):
    # Properties
    number = IntegerProperty(unique_index=True)
    details = JSONProperty()

    # Relationships
    device = RelationshipFrom('Device', 'USES_PORT')

    # Methods
    # None


class Vulnerability(StructuredNode):
    # Properties
    name = StringProperty(unique_index=True)

    # Relationships
    devices = RelationshipFrom('Device', 'HAS_VULNERABILITY')

    # Methods
    # None


class Group(StructuredNode):
    # Properties
    name = StringProperty(unique_index=True)

    # Relationships
    members = RelationshipFrom('Group', 'MEMBER_OF')

    # Methods
    # None


class Person(StructuredNode):
    # Properties
    user_name = UniqueIdProperty()
    account_disabled = BooleanProperty()
    account_expired = BooleanProperty()
    company = StringProperty()
    department = StringProperty()
    email = StringProperty()
    name_display = StringProperty()
    name_family = StringProperty()
    name_given = StringProperty()
    password_last_set = DateTimeProperty()
    phone = StringProperty()
    title = StringProperty()

    # Relationships
    device = RelationshipTo('Device', 'USES')
    groups = RelationshipTo('Group', 'MEMBER_OF')

    # Methods
    # None
