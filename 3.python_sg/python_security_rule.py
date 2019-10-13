import boto3

def remove_sgrules(sgid,vpc)
    sg= EC2_CLIENT.describe_security_groups(Filters=[
        {
            'Name': 'vpc-id',
            'Values': [vpc]
        },
        {
            'Name': 'group-id'
            'Values': [sgid]
        }
    ]
    )
    protocol_all = False

    compliance_type = "COMPLIANT"
    annotation_message = "Permission are correct"

    #printing security group rules
    for security_group_rule in sg["SecurityGroups"] [0] ["IpPermissions"]:

        #if the rule is all protocol is missing from port
         if "FromPort" not in security_group_rule:
             protocol_all=True
         for sgName, val in security_group_rule.items():
             try:
                 # Checking Ipv4
                if sgName == "IpRanges"
                    for r in val:
                        if r["CidrIp"] in ["0.0.0.0/0"]
                            print("Found the open world rule: ", sgid)
                            print("With CIDR IPV4 as: ", str(r["CidrIp"]))
                            v = list()
                            v.append(security_group_rule)
                            print("SG rule is: ", v)
                            if not protocol_all:
                                result = EC2_CLIENT.revoke_security_group_ingress(GroupId=sgid,IpProtocol=security_group_rule["IpProtocol"], CidrIp=r["CidrIp"],FromPort=security_group_rule["FromPort"], ToPort=security_group_rule["ToPort"])
                                print("result is: ", result)
                            else:
                                print("FromPort is missing....")
