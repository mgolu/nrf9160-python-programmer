#!/usr/bin/env python3
import logging
import argparse
import serial
from pynrfjprog import HighLevel

logging.basicConfig(level=logging.WARN)
log = logging.getLogger("programmer")  

cert_type = ["Root CA certificate", "Client certificate", "Client private key", "PSK", 
            "PSK identity", "Public key", "Device identity public key", "Reserved",
            "Endorsement private key", "Ownership key", "Nordic identity root CA",
            "Nordic base public key"]

def program(api, debugger, verify=False, app_firmware=None, modem_firmware=None):
    """
    Program an nRF9160 device attached to a JLink debugger
    @param HighLevel.API api: The HighLevel API instance to use
    @param Int debugger: Serial number of the debugger
    @param Boolean verify: Whether to verify the programmed firmware
    @param app_firmware: Path to the application firmware hex file
    @param modem_firmware: Path to the application firmware zip file
    """
    if app_firmware is None and modem_firmware is None:
        log.error("No firmware specified")
        return -1
    log.info("Flashing {}".format(debugger))
    """ These program options will erase the whole flash.
        The HEX file sent for the application must also contain the bootloader """
    program_options = HighLevel.ProgramOptions()
    if modem_firmware is not None:
        with HighLevel.IPCDFUProbe(api, debugger, HighLevel.CoProcessor.CP_MODEM) as probe:
            program_options.verify = HighLevel.VerifyAction.VERIFY_HASH if verify else HighLevel.VerifyAction.VERIFY_NONE
            program_options.erase_action = HighLevel.EraseAction.ERASE_SECTOR
            try:
                probe.program(modem_firmware, program_options)
            except:
                log.error("Not able to program modem")
                return -1
    if app_firmware is not None:
        with HighLevel.IPCDFUProbe(api, debugger, HighLevel.CoProcessor.CP_APPLICATION) as probe:
            if (probe.get_erase_protection()):
                try:
                    probe.recover()
                except:
                    log.error("Not able to recover device")
                    return -1
            program_options.verify = HighLevel.VerifyAction.VERIFY_READ if verify else HighLevel.VerifyAction.VERIFY_NONE
            try:
                probe.program(app_firmware, program_options)
            except:
                log.error("Not able to program device")
                return -1
    return 0

def list_credentials(comport, baud=115200):
    with serial.Serial(comport, baud, timeout=2) as ser:
        ser.write("AT%CMNG=1\r\n".encode())
        while True:
            line = str(ser.readline())
            if "OK" in line:
                break
            elif "ERROR" in line:
                return -1
            else:
                sp = line.split(':')
                if len(sp) > 1 and "%CMNG" in sp[0]:
                    certs = sp[1].split(',')
                    if int(certs[0]) <= 2147483647:   # Values above this are reserved for the modem
                        print("Tag: {}, Type: {}".format(certs[0], cert_type[int(certs[1])]))

def delete_credential(sec_tag, type, comport, baud=115200):
    with serial.Serial(comport, baud, timeout=2) as ser:
        if sec_tag <= 2147483647:
            ser.write("AT%CMNG=3,{:d},{:d}".format(sec_tag, type).encode())
            while True:
                line = str(ser.readline())
                if "OK" in line:
                    log.info("Security tag removed")
                    break
                elif "ERROR" in line:
                    log.warn("Security tag not removed")
                    break
        else:
            log.error("Security tag value too high")

def get_comport(api, debugger, index):
    with HighLevel.DebugProbe(api, debugger) as probe:
        probeinfo = probe.get_probe_info()
        port = ''
        for comport in probe.get_probe_info().com_ports:
            if comport.vcom == index:
                port = comport.path
    return port
    
def list_devices(api, debuggers):
    print("{:^20} {:^40} {:^40}".format('Probe', 'Device Type', 'Serial ports'))
    for sn in debuggers:
        with HighLevel.IPCDFUProbe(api, sn, HighLevel.CoProcessor.CP_APPLICATION) as probe:
            ports = ''
            for comport in probe.get_probe_info().com_ports:
                ports += "| {}: {} |".format(comport.vcom, comport.path)
            print("{:^20} {:^40} {:^40}".format(sn, str(probe.get_device_info().device_type), ports))

def main(args):
    with HighLevel.API() as api:
        snr = api.get_connected_probes()
        if len(snr) > 0:
            if args.list:
                list_devices(api, snr)
            if args.list_credentials:
                for sn in snr:
                    list_credentials(get_comport(api, sn, 0))
            if args.application is None and args.modem is None:
                log.info("No firmware specified")
            else:
                for sn in snr:
                    program(api, sn, args.verify, args.application, args.modem)
        else:
            log.error("No probe connected")
    
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Flash modem or application firmware on nRF9160 devices')
    parser.add_argument('-a', '--application', help='application firmware file')
    parser.add_argument('-m', '--modem', help='modem firmware file')
    parser.add_argument('-v', '--verify', action='store_true', help='verify after flashing')
    parser.add_argument('-l', '--list', action='store_true', help='list available devices')
    parser.add_argument('--list_credentials', action='store_true', help='list security credentials')
    main(parser.parse_args())
