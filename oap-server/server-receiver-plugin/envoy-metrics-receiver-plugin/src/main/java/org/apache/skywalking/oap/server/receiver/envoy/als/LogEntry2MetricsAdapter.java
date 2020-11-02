/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.apache.skywalking.oap.server.receiver.envoy.als;

import com.google.protobuf.Duration;
import com.google.protobuf.Timestamp;
import com.google.protobuf.UInt32Value;
import io.envoyproxy.envoy.data.accesslog.v2.AccessLogCommon;
import io.envoyproxy.envoy.data.accesslog.v2.HTTPAccessLogEntry;
import io.envoyproxy.envoy.data.accesslog.v2.HTTPRequestProperties;
import io.envoyproxy.envoy.data.accesslog.v2.HTTPResponseProperties;
import io.envoyproxy.envoy.data.accesslog.v2.TLSProperties;
import java.time.Instant;
import java.util.Optional;
import org.apache.skywalking.apm.network.servicemesh.v3.Protocol;
import org.apache.skywalking.apm.network.servicemesh.v3.ServiceMeshMetric;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.util.Optional.ofNullable;

/**
 * Adapt {@link HTTPAccessLogEntry} objects to {@link ServiceMeshMetric} builders.
 */
public final class LogEntry2MetricsAdapter {

    public static final String NON_TLS = "NONE";

    public static final String M_TLS = "mTLS";

    public static final String TLS = "TLS";

    /**
     * Adapt the {@code entry} partially, into a downstream metrics {@link ServiceMeshMetric.Builder}.
     *
     * @param entry the log entry to adapt.
     * @return the {@link ServiceMeshMetric.Builder} adapted from the given entry.
     */
    public static ServiceMeshMetric.Builder adaptToDownstreamMetrics(final HTTPAccessLogEntry entry) {
        final AccessLogCommon properties = entry.getCommonProperties();
        final long startTime = formatAsLong(properties.getStartTime());
        final long duration = formatAsLong(properties.getTimeToLastDownstreamTxByte());
        return adaptCommonPart(entry)
            .setStartTime(startTime)
            .setLatency((int) duration);
    }

    /**
     * Adapt the {@code entry} partially, into a upstream metrics {@link ServiceMeshMetric.Builder}.
     *
     * @param entry the log entry to adapt.
     * @return the {@link ServiceMeshMetric.Builder} adapted from the given entry.
     */
    public static ServiceMeshMetric.Builder adaptUpstreamMetrics(final HTTPAccessLogEntry entry) {
        final AccessLogCommon properties = entry.getCommonProperties();
        final long startTime = formatAsLong(properties.getTimeToFirstUpstreamTxByte());
        final long duration = formatAsLong(properties.getTimeToLastUpstreamRxByte());
        return adaptCommonPart(entry)
            .setStartTime(startTime)
            .setLatency((int) duration);
    }

    private static ServiceMeshMetric.Builder adaptCommonPart(final HTTPAccessLogEntry entry) {
        final AccessLogCommon properties = entry.getCommonProperties();
        final String endpoint = ofNullable(entry.getRequest()).map(HTTPRequestProperties::getPath).orElse("/");
        final int responseCode = ofNullable(entry.getResponse()).map(HTTPResponseProperties::getResponseCode).map(UInt32Value::getValue).orElse(200);
        final boolean status = responseCode >= 200 && responseCode < 400;
        final Protocol protocol = requestProtocol(entry.getRequest());
        final String tlsMode = parseTLS(properties.getTlsProperties());

        return ServiceMeshMetric.newBuilder()
                                .setEndpoint(endpoint)
                                .setResponseCode(Math.toIntExact(responseCode))
                                .setStatus(status)
                                .setProtocol(protocol)
                                .setTlsMode(tlsMode);
    }

    private static long formatAsLong(final Timestamp timestamp) {
        return Instant.ofEpochSecond(timestamp.getSeconds(), timestamp.getNanos()).toEpochMilli();
    }

    private static long formatAsLong(final Duration duration) {
        return Instant.ofEpochSecond(duration.getSeconds(), duration.getNanos()).toEpochMilli();
    }

    private static Protocol requestProtocol(final HTTPRequestProperties request) {
        if (request == null) {
            return Protocol.HTTP;
        }
        final String scheme = request.getScheme();
        if (scheme.startsWith("http")) {
            return Protocol.HTTP;
        }
        return Protocol.gRPC;
    }

    private static String parseTLS(final TLSProperties properties) {
        if (properties == null) {
            return NON_TLS;
        }
        if (isNullOrEmpty(Optional.ofNullable(properties.getLocalCertificateProperties())
                                  .orElse(TLSProperties.CertificateProperties.newBuilder().build())
                                  .getSubject())) {
            return NON_TLS;
        }
        if (isNullOrEmpty(Optional.ofNullable(properties.getPeerCertificateProperties())
                                  .orElse(TLSProperties.CertificateProperties.newBuilder().build())
                                  .getSubject())) {
            return TLS;
        }
        return M_TLS;
    }

}
