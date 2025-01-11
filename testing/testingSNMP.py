import asyncio
import concurrent.futures
from pysnmp.hlapi.asyncio.slim import Slim
from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, getCmd, ObjectType, ObjectIdentity
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType

def check_snmp_sync(ip):
    return asyncio.run(check_snmp(ip))

async def check_snmp(ip):
    with Slim(2) as slim:
        errorIndication, errorStatus, errorIndex, varBinds = await slim.get(
            "public",
            ip,
            161,
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
            timeout=1,
            retries=0,
        )

        if errorIndication:
            return ""
        
        elif errorStatus:
            return "{} at {}".format(
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                )
            
        else:
            for varBind in varBinds:
                return " = ".join([x.prettyPrint() for x in varBind])



def run():
    ips = [f'192.168.116.{i}' for i in range(224, 245)]
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(check_snmp_sync, ips))
    for i,result in enumerate(results):
        print(f"{i}: {result}")   

run()