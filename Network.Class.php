<?php
//
//
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//
//            NETWORK DEVICES - SNMP COMMUNICATION
//
// This class fetches snmp information from network devices,
// or is able to push some default settings to devices.
// Within run, this class will check several access parameters,
// so that legacy environments will work :-)
//
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//
// Initial Author:
//      Simon Brecht
//      simon(a)brecht.email
//
//////////////////////////////////////////////////////////////////
//
// CHANGELOG:
//
//      v0.1
//      04.09.2016, Brecht  - Initial Script
//
//////////////////////////////////////////////////////////////////
//
// BUGLIST:
//
//
//
//////////////////////////////////////////////////////////////////

class MySNMP
{
    public $host = '127.0.0.1';

    public $version = 2;
    public $community = 'public';

    public $sec_name = '';
    public $sec_level = 'authPriv';
    public $auth_protocol = 'SHA';
    public $auth_passphrase = '';
    public $priv_protocol = 'DES';
    public $priv_passphrase= '';

    public $timeout = 6000000;
    public $timeoutscan = 50000;
    public $retries = 3;


    public function checkCredentials()
    {
        // Communities to Try
        $v2_credentials = array("community1", "community2", "community3");

        // Array for v3
        $v3_sec_name[0] = 'v3-user';
        $v3_sec_level[0] = 'authPriv';
        $v3_auth_protocol[0] = 'SHA';
        $v3_auth_passphrase[0] = 'v3-pass1';
        $v3_priv_protocol[0] = 'DES';
        $v3_priv_passphrase[0] = 'v3-pass2';

        $tryoid = ".1.3.6.1.2.1.1.1.0";

        $_found = false;
        // First try v3, than v2
        for($i=0; $i<count($v3_sec_name); $i++)
        {
            if(!$_found)
            {
                print("* Trying Credential: " . $v3_sec_name[$i] . "\n");
                if(snmp3_get($this->host, $v3_sec_name[$i], $v3_sec_level[$i], $v3_auth_protocol[$i], $v3_auth_passphrase[$i], $v3_priv_protocol[$i], $v3_priv_passphrase[$i], $tryoid, $this->timeoutscan, 1))
                {
                    $this->version = 3;
                    $this->sec_name = $v3_sec_name[$i];
                    $this->sec_level = $v3_sec_level[$i];
                    $this->auth_protocol = $v3_auth_protocol[$i];
                    $this->auth_passphrase = $v3_auth_passphrase[$i];
                    $this->priv_protocol = $v3_priv_protocol[$i];
                    $this->priv_passphrase = $v3_priv_passphrase[$i];
                    $_found = true;
                    print("* Found Credential: ". $this->sec_name . "\n");
                }
            }
        }

        // Than try v2
        for($i=0; $i<count($v2_credentials); $i++)
        {
            if(!$_found)
            {
                print("* Trying Credential: " . $v2_credentials[$i] . "\n");
                if(snmp2_get($this->host, $v2_credentials[$i], $tryoid, $this->timeoutscan, 1))
                {
                    $this->version = 2;
                    $this->community = $v2_credentials[$i];
                    $_found = true;
                    print("* Found Credential: " . $this->community . "\n");
                }
            }
        }

        // Than try v1
        for($i=0; $i<count($v2_credentials); $i++)
        {
            if(!$_found)
            {
                print("* Trying Credential: " . $v2_credentials[$i] . "\n");
                if(snmpget($this->host, $v2_credentials[$i], $tryoid, $this->timeoutscan, 1))
                {
                    $this->version = 1;
                    $this->community = $v2_credentials[$i];
                    $_found = true;
                    print("* Found Credential: " . $this->community . "\n");
                }
            }
        }

        return $_found;

    }

    public function get_credential()
    {
        if($this->version<3) $credential = $this->community;
        if($this->version>2) $credential = $this->sec_name;
        return $credential;
    }

    // ==========================================================================
    // Global Host Information
    //
    //                                EXAMPLE
    // ==========================================================================
    //    Array
    //        (
    //              "{Hostname}"
    //              "{Description}"
    //              "{Location}"
    //              "{Contact}"
    //              "{Routing enabled?}"
    //              "{Services}"
    //              "{Procurve Serial}"
    //        )
    // ==========================================================================
    public function get_host_info()
    {
        $infos = array(".1.3.6.1.2.1.1.5.0",".1.3.6.1.2.1.1.1.0",".1.3.6.1.2.1.1.6.0",".1.3.6.1.2.1.1.4.0",".1.3.6.1.2.1.4.1.0",".1.3.6.1.2.1.1.7.0",".1.3.6.1.4.1.11.2.36.1.1.2.9.0");
        $ret = array();
        foreach($infos as $info)
        {
            $result = "";
            if($this->version<3) $result = snmpget($this->host, $this->community, $info, $this->timeout, $this->retries);
            if($this->version>2) $result = snmp3_get($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $info, $this->timeout, $this->retries);
            $result = str_replace("STRING:","",$result);
            $result = str_replace("INTEGER:","",$result);
            $result = str_replace('"', "", $result);
            $result = trim($result);
            array_push($ret,$result);
        }
        return $ret;
    }


    // ==========================================================================
    // ROUTING: HP PROCURVE | RFC Routing Table
    //
    //                                EXAMPLE
    // ==========================================================================
    //    [0.0.0.0] => Array
    //        (
    //            [ipRouteDest] => 0.0.0.0
    //            [ipRouteIfIndex] => 296
    //            [ipRouteMetric1] => 250
    //            [ipRouteMetric2] => 0
    //            [ipRouteMetric3] => -1
    //            [ipRouteMetric4] => -1
    //            [ipRouteNextHop] => 10.250.100.1
    //            [ipRouteType] => indirect(4)
    //            [ipRouteProto] => netmgmt(3)
    //            [ipRouteAge] => 18912655
    //            [ipRouteMask] => 0.0.0.0
    //            [ipRouteMetric5] => -1
    //            [ipRouteInfo] => OID: SNMPv2-SMI::zeroDotZero
    //        )
    // ==========================================================================
    public function get_routing_rfc1213()
    {
        $oid = ".1.3.6.1.2.1.4.21";
        if($this->version<3) $table = snmprealwalk($this->host, $this->community, $oid, $this->timeout, $this->retries);
        if($this->version>2) $table = snmp3_real_walk($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $oid, $this->timeout, $this->retries);
        while($value = current($table))
        {
            preg_match('/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/', key($table), $route_dst);
            $attr = str_replace("RFC1213-MIB::","",key($table));
            $attr = str_replace("." . $route_dst[0],"",$attr);
            $val = str_replace("INTEGER:", "", $value);
            $val = str_replace("IpAddress:", "", $val);
            $val = trim($val);
            $route[$route_dst[0]][$attr] = $val;
            next($table);
        }
        return $route;
    }





    // ==========================================================================
    // ROUTING: CISCO | RFC ipCidrRoute Table
    //
    //                                EXAMPLE
    // ==========================================================================
    //    [10.250.100.0] => Array
    //        (
    //            [ipCidrRouteDest] => 10.250.100.0
    //            [ipCidrRouteMask] => 255.255.255.0
    //            [ipCidrRouteTos] => 0
    //            [ipCidrRouteNextHop] => 192.168.0.1
    //            [ipCidrRouteIfIndex] => 0
    //            [ipCidrRouteType] => remote(4)
    //            [ipCidrRouteProto] => bgp(14)
    //            [ipCidrRouteAge] => 448733
    //            [ipCidrRouteInfo] => OID: SNMPv2-SMI::zeroDotZero
    //            [ipCidrRouteNextHopAS] => 0
    //            [ipCidrRouteStatus] => active(1)
    //        )
    // ==========================================================================
    public function get_routing_rfc2096()
    {
        $oid = ".1.3.6.1.2.1.4.24.4";
        if($this->version<3) $table = snmprealwalk($this->host, $this->community, $oid, $this->timeout, $this->retries);
        if($this->version>2) $table = snmp3_real_walk($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $oid, $this->timeout, $this->retries);
        while($value = current($table))
        {
            preg_match('/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/', key($table), $route_dst);
            preg_match('/([0-9]+\.)+[0-9]+/', key($table), $remove);
            $attr = str_replace("IP-FORWARD-MIB::","",key($table));
            $attr = str_replace("." . $remove[0],"",$attr);
            $val = str_replace("INTEGER:", "", $value);
            $val = str_replace("IpAddress:", "", $val);
            $val = str_replace("STRING:", "", $val);
            $val = trim($val);
            $route[$route_dst[0]][$attr] = $val;
            next($table);
        }
        return $route;
    }


    // ==========================================================================
    // ARP-TABLE: Global | RFC ipNetToMediaPhysAddress Table
    //
    //                                EXAMPLE
    // ==========================================================================
    //    [10.250.100.1] => Array
    //        (
    //            [ipNetToMediaPhysAddress] => 00:70:4D:38:3E:F2
    //        )
    // ==========================================================================
    public function get_arp_rfc4293()
    {
        $oid = ".1.3.6.1.2.1.4.22.1.2";
        if($this->version<3) $table = snmprealwalk($this->host, $this->community, $oid, $this->timeout, $this->retries);
        if($this->version>2) $table = snmp3_real_walk($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $oid, $this->timeout, $this->retries);
        while($value = current($table))
        {
            preg_match('/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/', key($table), $ipaddr);
            preg_match('/([0-9]+\.)+[0-9]+/', key($table), $remove);
            $attr = str_replace("IP-MIB::", "", key($table));
            $attr = str_replace("." . $remove[0], "", $attr);
            $val = str_replace("INTEGER:", "", $value);
            $val = str_replace("IpAddress:", "", $val);
            $val = str_replace("STRING:", "", $val);
            $val = strtoupper(trim($val));
            $val_c = explode(":", $val);
            for($i=0; $i<count($val_c); $i++)
            {
                if(strlen($val_c[$i])<2)
                {
                    $val_c[$i] .= "0";
                }
            }
            $val = implode(":", $val_c);
            $arp[$ipaddr[0]][$attr] = $val;
            next($table);
        }
        return $arp;
    }



    // ==========================================================================
    // INTERFACE-TABLE: Global | RFC ifDescr Table
    //
    //                                EXAMPLE
    // ==========================================================================
    //    [6] => Array
    //        (
    //            [ifDescr] => GigabitEthernet0
    //            [ifAlias] => DEFAULT_VLAN
    //        )
    // ==========================================================================
    public function get_interface_rfc1213()
    {
        $oid = ".1.3.6.1.2.1.2.2.1.2";
        if($this->version<3) $table = snmprealwalk($this->host, $this->community, $oid, $this->timeout, $this->retries);
        if($this->version>2) $table = snmp3_real_walk($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $oid, $this->timeout, $this->retries);
        while($value = current($table))
        {
            preg_match('/[0-9]+$/', key($table), $ifindex);
            $attr = str_replace("IF-MIB::", "", key($table));
            $attr = str_replace("." . $ifindex[0], "", $attr);
            $val = str_replace("INTEGER:", "", $value);
            $val = str_replace("IpAddress:", "", $val);
            $val = str_replace("STRING:", "", $val);
            $iface[$ifindex[0]][$attr] = $val;
            next($table);
        }
        $table = array();
        $oid = ".1.3.6.1.2.1.31.1.1.1.18";
        if($this->version<3) $table = snmprealwalk($this->host, $this->community, $oid, $this->timeout, $this->retries);
        if($this->version>2) $table = snmp3_real_walk($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $oid, $this->timeout, $this->retries);
        while($value = current($table))
        {
            preg_match('/[0-9]+$/', key($table), $ifindex);
            $attr = str_replace("IF-MIB::", "", key($table));
            $attr = str_replace("." . $ifindex[0], "", $attr);
            $val = str_replace("INTEGER:", "", $value);
            $val = str_replace("IpAddress:", "", $val);
            $val = str_replace("STRING:", "", $val);
            $iface[$ifindex[0]][$attr] = $val;
            next($table);
        }
        return $iface;
    }


    // ==========================================================================
    // MAC-TABLE: Global | RFC dot1dTpFdbAddress Table
    //
    //                                EXAMPLE
    // ==========================================================================
    //    [FC:3F:DB:FA:44:D8] => Array
    //        (
    //            [dot1dTpFdbAddress] => 252.63.219.250.68.216
    //        )
    // ==========================================================================
    public function get_mac_rfc4188()
    {
        $oid = ".1.3.6.1.2.1.17.4.3.1.1";
        if($this->version<3) $table = snmprealwalk($this->host, $this->community, $oid, $this->timeout, $this->retries);
        if($this->version>2) $table = snmp3_real_walk($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $oid, $this->timeout, $this->retries);
        while($value = current($table))
        {
            preg_match('/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/', key($table), $macindex);
            $attr = str_replace("SNMPv2-SMI::mib-2.17.4.3.1.1", "dot1dTpFdbAddress", key($table));
            $attr = str_replace("." . $macindex[0], "", $attr);
            $val = str_replace("Hex-STRING:", "", $value);
            $val = strtoupper(trim($val));
            $val_c = explode(" ", $val);
            $val = implode(":", $val_c);
            $mac[$val][$attr] = $macindex[0];
            next($table);
        }
        return $mac;
    }


    // ==========================================================================
    // CAM-TABLE: Global | RFC dot1dTpFdbPort Table
    //
    //                                EXAMPLE
    // ==========================================================================
    //    [11] => Array
    //        (
    //            [0] => 180.199.153.116.130.228
    //            [1] => 180.199.153.116.130.229
    //        )
    // ==========================================================================
    public function get_cam_rfc4188()
    {
        $oid = ".1.3.6.1.2.1.17.4.3.1.2";
        if($this->version<3) $table = snmprealwalk($this->host, $this->community, $oid, $this->timeout, $this->retries);
        if($this->version>2) $table = snmp3_real_walk($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $oid, $this->timeout, $this->retries);
        $cam = array();
        while($value = current($table))
        {
            preg_match('/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/', key($table), $macindex);
            $val = str_replace("INTEGER:", "", $value);
            $val = trim($val);
            if(array_key_exists($val, $cam))
            {
                array_push($cam[$val], $macindex[0]);
            }
            else
            {
                $cam[$val][0] = $macindex[0];
            }
            next($table);
        }
        return $cam;
    }


    // ==========================================================================
    // LLDP-TABLE: Global | Procurve Specific
    //
    //                                EXAMPLE
    // ==========================================================================
    //    [11] => Array
    //        (
    //            [0] => 10.250.100.1
    //        )
    // ==========================================================================
    public function get_lldp_partner()
    {
        $oid = ".1.0.8802.1.1.2.1.4.2.1.3";
        if($this->version<3) $table = snmprealwalk($this->host, $this->community, $oid, $this->timeout, $this->retries);
        if($this->version>2) $table = snmp3_real_walk($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $oid, $this->timeout, $this->retries);
        $lldp = array();
        while($value = current($table))
        {
            preg_match('/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/', key($table), $partner);
            $val = str_replace("iso.0.8802.1.1.2.1.4.2.1.3.0.", "",key($table));
            preg_match('/^[0-9]+/', $val, $ifindex);
            $val = $ifindex[0];
            if(array_key_exists($val, $lldp))
            {
                array_push($lldp[$val], $partner[0]);
            }
            else
            {
                $lldp[$val][0] = $partner[0];
            }
            next($table);
        }
        return $lldp;
    }

    
    // ==========================================================================
    // Set some Defaults to Procurve Switches,
    // run without any arguments.
    // ==========================================================================
    public function set_defaults()
    {
        $defaults = array(array(".1.3.6.1.4.1.11.2.14.11.1.3.5.0", "i", "1"),       // hpicfDownloadTftpConfig = disable
                          array(".1.3.6.1.4.1.11.2.14.11.1.3.6.0", "i", "2"),       // hpicfDownloadTftpServerConfig = disable
                          array(".1.3.6.1.4.1.11.2.14.11.5.1.7.1.20.6.0", "i", "1") // hpSwitchSshFileServerAdminStatus = enable
                          );
        foreach($defaults as $option)
        {
            try
            {
                if($this->version<3) snmpset($this->host, $this->community, $option[0], $option[1], $option[2], $this->timeout, $this->retries);
                if($this->version>2) snmp3_set($this->host, $this->sec_name, $this->sec_level, $this->auth_protocol, $this->auth_passphrase, $this->priv_protocol, $this->priv_passphrase, $option[0], $option[1], $option[2], $this->timeout, $this->retries);
            }
            catch(Exception $e)
            {
                print("Could not set SNMP-Settings, Error: ".$e);
            }
        }

    }
}
?>
