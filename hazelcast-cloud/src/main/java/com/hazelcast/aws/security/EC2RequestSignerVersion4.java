/*
 * Copyright (c) 2008-2013, Hazelcast, Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hazelcast.aws.security;

import com.hazelcast.aws.impl.DescribeInstances;
import com.hazelcast.config.AwsConfig;

import sun.security.jca.GetInstance.Instance;

public class EC2RequestSignerVersion4 extends EC2RequestSigner {
//    private static final String HTTP_VERB = "GET\n";
//    private static final String HTTP_REQUEST_URI = "/\n";
//    private final String secretKey;

    private final AwsConfig config;

    public EC2RequestSignerVersion4(AwsConfig config) {
        this.config = config;

        AWSCredentials credentials = new BasicAWSCredentials(config.getAccessKey(), config.getSecretKey());
        AmazonEC2Client client = new AmazonEC2Client(credentials);
        client.setEndpoint(config.getRegion());

        DescribeInstancesResult result = client.describeInstances();
        for (Reservation reservation : result.getReservations()) {
            for (Instance instance : reservation.getInstances()) {
                for (GroupIdentifier group : instance.getSecurityGroups()) {
                    if (group.getGroupName().equals("devoxx hunt application")) {
                        System.out.println("EC2 instance " + instance.getPrivateIpAddress());
                        hazelcastConfig.addAddress(instance.getPrivateIpAddress(), instance.getPrivateIpAddress() + ":5701");
                    }
                }
            }
        }
    }

    @Override
    public void sign(DescribeInstances request, String endpoint) {
    }

/*
    public EC2RequestSignerVersion4(String secretKey) {
        if (secretKey == null) {
            throw new IllegalArgumentException("AWS secret key is required!");
        }
        this.secretKey = secretKey;
    }

    @Override
    public void sign(DescribeInstances request, String endpoint) {
        String canonicalizedQueryString = getCanonicalizedQueryString(request, endpoint);
        String canonicalizedHeaderString = getCanonicalizedHeaderString(endpoint);
        String stringToSign = HTTP_VERB + HTTP_REQUEST_URI + canonicalizedQueryString + "\n" + canonicalizedHeaderString;
        String signature = signTheString(stringToSign);
        request.putSignature(signature);
    }

    private String signTheString(String stringToSign) {
        String signature = null;
        try {
            signature = RFC2104HMAC.calculateRFC2104HMAC(stringToSign, secretKey);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        return signature;
    }

    private String getCanonicalizedQueryString(DescribeInstances request, String endpoint) {
        List<String> components = getListOfEntries(request.getAttributes());
        addSignatureComponents(request, components, endpoint);
        Collections.sort(components);
        return getCanonicalizedQueryString(components);
    }

    private void addSignatureComponents(DescribeInstances request, List<String> components, String endpoint) {
        components.add(AwsURLEncoder.urlEncode("X-Amz-Credential") + "=" + AwsURLEncoder.urlEncode(request.getAccessKey() + "/" + endpoint + "/ec2/aws4_request"));
    }

    private void addComponents(List<String> components, Map<String, String> attributes, String key) {
        components.add(AwsURLEncoder.urlEncode(key) + "=" + AwsURLEncoder.urlEncode(attributes.get(key)));
    }

    private List<String> getListOfEntries(Map<String, String> entries) {
        List<String> components = new ArrayList<String>();
        for (String key : entries.keySet()) {
            addComponents(components, entries, key);
        }
        return components;
    }

    private String getCanonicalizedQueryString(List<String> list) {
        Iterator<String> it = list.iterator();
        StringBuilder result = new StringBuilder(it.next());
        while (it.hasNext()) {
            result.append("&").append(it.next());
        }
        return result.toString();
    }

    private String getCanonicalizedHeaderString(String endpoint) {
        return "host:" + AwsURLEncoder.urlEncode(endpoint) + "\n";
    }
*/
}
