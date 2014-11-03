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

package com.hazelcast.aws.impl;

import com.hazelcast.aws.security.EC2RequestSigner;
import com.hazelcast.aws.security.EC2RequestSignerVersion2;
import com.hazelcast.aws.security.EC2RequestSignerVersion4;
import com.hazelcast.aws.utility.CloudyUtility;
import com.hazelcast.config.AwsConfig;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import static com.hazelcast.aws.impl.Constants.DOC_VERSION;
import static com.hazelcast.aws.impl.Constants.GET;

public class DescribeInstances {

    private final EC2RequestSigner rs;
    private final AwsConfig awsConfig;

    private Map<String, String> attributes = new HashMap<String, String>();

    public DescribeInstances(AwsConfig awsConfig) {
        if (awsConfig == null) {
            throw new IllegalArgumentException("AwsConfig is required!");
        }
        if (awsConfig.getAccessKey() == null) {
            throw new IllegalArgumentException("AWS access key is required!");
        }
        String signatureVersion = awsConfig.getSignatureVersion();
        if ("2".equals(signatureVersion)) {
            rs = new EC2RequestSignerVersion2(awsConfig.getSecretKey());
            attributes.put("Action", this.getClass().getSimpleName());
            attributes.put("Version", DOC_VERSION);
            attributes.put("SignatureVersion", signatureVersion);
            attributes.put("SignatureMethod", "HmacSHA256");
            attributes.put("AWSAccessKeyId", awsConfig.getAccessKey());
            attributes.put("Timestamp", getFormattedTimestamp());
        } else {
            rs = new EC2RequestSignerVersion4(awsConfig);
        }
        this.awsConfig = awsConfig;
    }

    /**
     * Formats date as ISO 8601 timestamp
     */
    private String getFormattedTimestamp() {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        return df.format(new Date());
    }

    /**
     * Formats date as ISO 8601 timestamp
     */
    private String getFormattedTimestamp2() {
        SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        return df.format(new Date());
    }

    public String getQueryString() {
        return CloudyUtility.getQueryString(attributes);
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public String getAccessKey() {
        return awsConfig.getAccessKey();
    }

    public void putSignature(String value) {
        attributes.put("Signature", value);
    }

    public Map<String, String> execute(String endpoint) throws Exception {
        rs.sign(this, endpoint);
        InputStream stream = callService(endpoint);
        return CloudyUtility.unmarshalTheResponse(stream, awsConfig);
    }

    private InputStream callService(String endpoint) throws Exception {
        String query = getQueryString();
        URL url = new URL("https", endpoint, -1, "/" + query);
        HttpURLConnection httpConnection = (HttpURLConnection) (url.openConnection());
        httpConnection.setRequestMethod(GET);
        httpConnection.setDoOutput(true);
        httpConnection.connect();
        return httpConnection.getInputStream();
    }
}
