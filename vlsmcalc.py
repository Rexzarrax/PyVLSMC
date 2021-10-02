#Resources for testing: https://subnettingpractice.com/vlsm.html

SUBNETS = {
    0 : {"mask":[0,0,0,0], "usablehosts": 4294967794, "magicnum" : ["N/A"] },
    1 : {"mask":[128,0,0,0], "usablehosts": 2147483646, "magicnum" : [128,0,0,0] },
    2 : {"mask":[192,0,0,0], "usablehosts": 1073741822, "magicnum" : [64,0,0,0] },
    3 : {"mask":[224,0,0,0], "usablehosts": 536870910, "magicnum" : [32,0,0,0] },
    4 : {"mask":[240,0,0,0], "usablehosts": 268435454, "magicnum" : [16,0,0,0] },
    5 : {"mask":[248,0,0,0], "usablehosts": 134217726, "magicnum" : [8,0,0,0] },
    6 : {"mask":[252,0,0,0], "usablehosts": 67108862, "magicnum" : [4,0,0,0] },
    7 : {"mask":[254,0,0,0], "usablehosts": 33554430, "magicnum" : [2,0,0,0] },
    8 : {"mask":[255,0,0,0], "usablehosts": 16777214, "magicnum" : [1,0,0,0] },
    9 : {"mask":[255,128,0,0], "usablehosts": 8388606, "magicnum" : [0,128,0,0] },
    10 : {"mask":[255,192,0,0], "usablehosts": 4194302, "magicnum" : [0,64,0,0] },
    11 : {"mask":[255,224,0,0], "usablehosts": 2097150, "magicnum" : [0,32,0,0] },
    12 : {"mask":[255,240,0,0], "usablehosts": 1048574, "magicnum" : [0,16,0,0] },
    13 : {"mask":[255,248,0,0], "usablehosts": 524286, "magicnum" : [0,8,0,0] },
    14 : {"mask":[255,252,0,0], "usablehosts": 262142, "magicnum" : [0,4,0,0] },
    15 : {"mask":[255,254,0,0], "usablehosts": 131070, "magicnum" : [0,2,0,0] },
    16 : {"mask":[255,255,0,0], "usablehosts": 65534, "magicnum" : [0,1,0,0] },
    17 : {"mask":[255,255,128,0], "usablehosts": 32766, "magicnum" : [0,0,128,0] },
    18 : {"mask":[255,255,192,0], "usablehosts": 16382, "magicnum" : [0,0,64,0] },
    19 : {"mask":[255,255,224,0], "usablehosts": 8190, "magicnum" : [0,0,32,0] },
    20 : {"mask":[255,255,240,0], "usablehosts": 4094, "magicnum" : [0,0,16,0] },
    21 : {"mask":[255,255,248,0], "usablehosts": 2046, "magicnum" : [0,0,8,0] },
    22 : {"mask":[255,255,252,0], "usablehosts": 1022, "magicnum" : [0,0,4,0] },
    23 : {"mask":[255,255,254,0], "usablehosts": 510, "magicnum" : [0,0,2,0] },
    24 : {"mask":[255,255,255,0], "usablehosts": 254, "magicnum" : [0,0,1,0] },
    25 : {"mask":[255,255,255,128], "usablehosts": 126, "magicnum" : [0,0,0,128] },
    26 : {"mask":[255,255,255,192], "usablehosts": 62, "magicnum" : [0,0,0,64] },
    27 : {"mask":[255,255,255,224], "usablehosts": 30, "magicnum" : [0,0,0,32] },
    28 : {"mask":[255,255,255,240], "usablehosts": 14, "magicnum" : [0,0,0,16] },
    29 : {"mask":[255,255,255,248], "usablehosts": 6, "magicnum" : [0,0,0,8] },
    30 : {"mask":[255,255,255,252], "usablehosts": 2, "magicnum" : [0,0,0,4] },
    31 : {"mask":[255,255,255,254], "usablehosts": 2, "magicnum" : [0,0,0,2] },
    32 : {"mask":[255,255,255,255], "usablehosts": 1, "magicnum" : [0,0,0,1] }
}

class Network_VLSM:
    def __init__(self, given_network_id, given_cidr, list_of_subnetworks):
        self.dict_of_given_subnetworks = SortType(list_of_subnetworks,0)
        self.str_given_network_id = given_network_id
        self.int_given_cidr = given_cidr
        self.arr_given_network_id = []
        self.int_total_hosts = 0
        self.int_total_hosts_available = 0
        self.network_class = ""
        self.arr_network_id = [[],[],[],[]]

        dict_of_subnetworks = {}

        for key in self.dict_of_given_subnetworks:
            dict_of_subnetworks[key] = {"Hosts" : self.dict_of_given_subnetworks[key]}

        self.dict_of_subnetworks = dict_of_subnetworks

        arr_given_network_id = IPProcessing(self.str_given_network_id)
        self.arr_given_network_id = arr_given_network_id
        self.int_total_hosts = TotalHosts(self.dict_of_subnetworks)

        int_available_hosts = SUBNETS[self.int_given_cidr]["usablehosts"]
        print("Avalibale hosts: "+str(int_available_hosts))
        print("Required Hosts: "+str(self.int_total_hosts))
        if self.int_total_hosts >= int_available_hosts:
            print("Error, too many hosts("+str(int_available_hosts)+") for subnet!")
            exit()

        self.network_class = DetermineClass(self.int_given_cidr)
        #print(str(self.dict_of_subnetworks))

        CheckPrivate(self.arr_given_network_id)
        
        subnet_binary = GetBinary(self.int_given_cidr)

        CalcWildcard(subnet_binary)

        binary_ip = ConvertToBinary(arr_given_network_id)

        #print(str(binary_ip))

        binary_ip_gateway = ConfirmIPGateway(subnet_binary, binary_ip)

        #print(str(binary_ip_gateway))

        ip_string = []
        for octet in binary_ip_gateway:
            ip_string.append(int(ArrayToString(octet),2))
        

        arr_last_ip = ip_string
        for network_name,sub_info in self.dict_of_subnetworks.items():
            network_size = self.dict_of_subnetworks[network_name]['Hosts']
            network_subnet = ConvertToBinary(CheckHosts(network_size))
            cidr = 0
            for octet in range (0,4):
                for bit in range (0,8): 
                    if network_subnet[octet][bit] == 1:
                        cidr += 1

            #self.dict_of_subnetworks[network_name]["subnetwildcard"] = CalcWildcard(network_subnet)
            self.dict_of_subnetworks[network_name]["gatewayip"] = arr_last_ip
            self.dict_of_subnetworks[network_name]["cidr"] = cidr
            self.dict_of_subnetworks[network_name]["subnet"] = SUBNETS[self.dict_of_subnetworks[network_name]["cidr"]]["mask"]
            
            arr_last_ip = BinaryAdder(ConvertToBinary(SUBNETS[cidr]['magicnum']),ConvertToBinary(arr_last_ip))

def main():
    #network name/ number of hosts required in the sub-network
    vlsm1 = Network_VLSM("172.16.1.0",22,{"HR" : 100, "Board" : 11, "General" : 550, "Sales" : 25, "Accounts" : 20})
    print(str(vlsm1.dict_of_subnetworks))

    vlsm2 = Network_VLSM("192.168.1.0",24,{"IOT" : 100, "Servers" : 11, "General" : 50})
    print(str(vlsm2.dict_of_subnetworks))

def BinaryAdder(arr_wildcard, arr_gateway):
    str_subnet_octet = ""
    str_gateway_octet = ""
    for octet in range (0,4):
        for bit in range (0,8): 
            str_subnet_octet += str(arr_wildcard[octet][bit])
            str_gateway_octet += str(arr_gateway[octet][bit])
        
    arr_added_binary = str(bin(int(str_subnet_octet,2)+int(str_gateway_octet,2)))

    arr_added_binary_clean = arr_added_binary.split("0b")[1]
    arr_added_binary_split = []

    arr_added_binary_split.append(arr_added_binary_clean[0:8])
    arr_added_binary_split.append(arr_added_binary_clean[8:16])
    arr_added_binary_split.append(arr_added_binary_clean[16:24])
    arr_added_binary_split.append(arr_added_binary_clean[24:32])

    arr_ip = []
    for x in range(0,4):
        arr_ip.append(int(arr_added_binary_split[x],2))
    #print(str(arr_ip))
    return arr_ip

def ConfirmIPGateway(subnet_binary, binary_ip):
    binary_ip_gateway = [[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0]]
    invalidIP = True
    for octet in range (0,4):
        for bit in range (0,8):
            if subnet_binary[octet][bit] == 0:
                binary_ip_gateway[octet][bit] = 0
            else:
                binary_ip_gateway[octet][bit] = binary_ip[octet][bit]
            if binary_ip[octet][bit] == binary_ip_gateway[octet][bit] and invalidIP:
                print("Gateway IP is not possible with current cidr, changing to be valid...")
                invalidIP = False
    return binary_ip_gateway

def ConvertToBinary(ip):
    binary_ip = [[],[],[],[]]
    for octet in range (0,4):
        ip_octet = ip[octet]
        if ip[octet] != 0:
            while(ip_octet>0):
                d=ip_octet%2
                binary_ip[octet].append(d)
                ip_octet=ip_octet//2
        while len(binary_ip[octet]) <= 7:
            binary_ip[octet].append(0)
        binary_ip[octet].reverse()
    return binary_ip

def CalcWildcard(subnet_binary):
    wildcard = [[],[],[],[]]
    for octet in range (0,4):
        for bit in range (0,8): 
            if subnet_binary[octet][bit] == 1:
                wildcard[octet].append(0)
            else:
                wildcard[octet].append(1)
    #print(str(wildcard))
    return wildcard

def ArrayToString(array):
    return_str = ""
    for bit in range (0,len(array)):
        return_str += str(array[bit])
    #print(return_str)
    return return_str

def SortType(to_sort, sort):
    #0 = sort ascending hosts 
    #1 = sort descending hosts 
    switcher = {
    0: SizeSort(to_sort, True),
    1: SizeSort(to_sort, False),
    }
    return switcher.get(sort, "Invalid sort option")

def DetermineClass(cidr):
    networkclass = ""
    if cidr <= 15 and cidr >= 8:
        networkclass = "Class A"
    elif cidr <= 23:
        networkclass = "Class B"
    elif cidr <= 30:
        networkclass = "Class C"
    return networkclass

def GetBinary(cidr):
    network_binary = [[],[],[],[]]
    bits = 0
    for octet in range (0,4):
        for bit in range (0,8):
            if bits+1 <= cidr:
                network_binary[octet].append(1)
            else:
                network_binary[octet].append(0)
            bits = bits + 1
    #print(str(network_binary))
    return network_binary

def SizeSort(to_sort, order):
    sorted_vlsm = dict(sorted(to_sort.items(),key= lambda x:x[1],reverse = order))

    return sorted_vlsm

def TotalHosts(list_hosts):
    total = 0
    for key in list_hosts:
        total += list_hosts[key]["Hosts"]
    #print("Total Required Hosts: " + str(total))
    return total

def IPProcessing(ip):
    ip_array = ip.split(".")
    ip_array_int = [0,0,0,0]

    for octet in range (0,3):
        ip_array_int[octet] = int(ip_array[octet])
    return ip_array_int

def CheckPrivate(v4address):
    #print(v4address)
    if v4address[0] == 10:
        print("Network is private")

    elif v4address[0] == 192 and v4address[1] == 168:
        print("Network is private")

    elif v4address[0] == 172 and 16 <= v4address[2] <= 31:   
        print("Network is private")
    else:
        print("Network is NOT private")

def CheckHosts(hosts):
    for x in range (0,32):
        if hosts > SUBNETS[x]["usablehosts"]:
            #print(SUBNETS[x-1]["mask"])
            return SUBNETS[x-1]["mask"]

if __name__ == "__main__":
    main()