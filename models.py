from datetime import datetime

import pytz
from neomodel import BooleanProperty, DateTimeProperty, IntegerProperty, Relationship, StructuredRel
from neomodel import RelationshipFrom
from neomodel import RelationshipTo
from neomodel import StringProperty
from neomodel import StructuredNode
from neomodel import UniqueIdProperty


##
## Mixins
##

class IpMixin(object):
    hostname = UniqueIdProperty()
    ip = StringProperty(unique_index=True)
    mac_address = StringProperty()


class PluggableMixin(object):
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

# We are in end user land, not data center land.
# Router -> Switch -> NetworkModule -> InterfaceCard -> Interface -> Device -> Segment

class NetworkingDevice(StructuredNode, IpMixin):
    __abstract_node__ = True

    # Properties
    type = StringProperty(required=True)
    vendor = StringProperty()
    model = StringProperty()
    version = StringProperty()

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
    reported_y = BooleanProperty()
    reported_z = BooleanProperty()

    hw_model = StringProperty()
    hw_vendor = StringProperty()
    linux_secure_connector = BooleanProperty()
    linux_ssh = BooleanProperty()
    mac_ssh = BooleanProperty()
    netbios_domain = StringProperty()
    netbios_hostname = StringProperty()
    network_function = StringProperty()
    nic_vendor = StringProperty()
    num_hosts_on_port = IntegerProperty()
    os = StringProperty()
    os_class = StringProperty()
    os_fingerprint = StringProperty()
    win_av_installed = StringProperty()
    win_av_running = StringProperty()
    win_av_update_last = DateTimeProperty()
    win_manageable_deployment_type = StringProperty()
    win_manageable_domain = BooleanProperty()
    win_manageable_secure = BooleanProperty()
    win_secure_systray = StringProperty()
    win_secure_version = StringProperty()

    # Relationships
    interface = RelationshipTo('Interface', 'PHYSICAL_UPLINK')
    open_ports = RelationshipTo('Port', 'PORT_USAGE')
    segment = RelationshipTo('Segment', 'SEGMENT')
    vulnerabilities = RelationshipTo('Vulnerability', 'HAS_VULNERABILITY')
    user = RelationshipFrom('Person', 'USES')

    # Methods
    # None


class EndUserDevice(Device):
    # Properties
    user_name = StringProperty()
    function = StringProperty(default='End-User')
    testx = StringProperty(default='XX')

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


class Port(StructuredNode):
    # Properties
    name = StringProperty(unique_index=True)
    purpose = StringProperty()

    # Relationships
    device = RelationshipFrom('Device', 'PORT_USAGE')

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
    name = StringProperty()

    # Relationships
    members = RelationshipFrom('Group', 'MEMBER_OF')

    # Methods
    # None


class Person(StructuredNode):
    # Properties
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
