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

package org.apache.skywalking.oap.server.receiver.envoy.als.k8s;

import io.envoyproxy.envoy.api.v2.core.Address;
import io.envoyproxy.envoy.api.v2.core.SocketAddress;
import io.envoyproxy.envoy.data.accesslog.v2.AccessLogCommon;
import io.envoyproxy.envoy.data.accesslog.v2.HTTPAccessLogEntry;
import io.envoyproxy.envoy.service.accesslog.v2.StreamAccessLogsMessage;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.skywalking.apm.network.common.v3.DetectPoint;
import org.apache.skywalking.apm.network.servicemesh.v3.ServiceMeshMetric;
import org.apache.skywalking.oap.server.receiver.envoy.EnvoyMetricReceiverConfig;
import org.apache.skywalking.oap.server.receiver.envoy.als.AbstractALSAnalyzer;
import org.apache.skywalking.oap.server.receiver.envoy.als.Role;
import org.apache.skywalking.oap.server.receiver.envoy.als.ServiceMetaInfo;

import static org.apache.skywalking.oap.server.receiver.envoy.als.LogEntry2MetricsAdapter.NON_TLS;
import static org.apache.skywalking.oap.server.receiver.envoy.als.LogEntry2MetricsAdapter.adaptToDownstreamMetrics;
import static org.apache.skywalking.oap.server.receiver.envoy.als.LogEntry2MetricsAdapter.adaptUpstreamMetrics;

/**
 * Analysis log based on ingress and mesh scenarios.
 */
@Slf4j
public class K8sALSServiceMeshHTTPAnalyzer extends AbstractALSAnalyzer {
    protected K8SServiceRegistry serviceRegistry;

    @Override
    public String name() {
        return "k8s-mesh";
    }

    @Override
    @SneakyThrows
    public void init(EnvoyMetricReceiverConfig config) {
        serviceRegistry = new K8SServiceRegistry(config);
        serviceRegistry.start();
    }

    @Override
    public List<ServiceMeshMetric.Builder> analysis(StreamAccessLogsMessage.Identifier identifier, HTTPAccessLogEntry entry, Role role) {
        if (serviceRegistry.isEmpty()) {
            return Collections.emptyList();
        }
        switch (role) {
            case PROXY:
                return analyzeProxy(entry);
            case SIDECAR:
                return analyzeSideCar(entry);
        }

        return Collections.emptyList();
    }

    protected List<ServiceMeshMetric.Builder> analyzeSideCar(final HTTPAccessLogEntry entry) {
        final AccessLogCommon properties = entry.getCommonProperties();
        if (properties == null) {
            return Collections.emptyList();
        }
        final String cluster = properties.getUpstreamCluster();
        if (cluster == null) {
            return Collections.emptyList();
        }

        final List<ServiceMeshMetric.Builder> sources = new ArrayList<>();

        final Address downstreamRemoteAddress = properties.getDownstreamRemoteAddress();
        final ServiceMetaInfo downstreamService = find(downstreamRemoteAddress.getSocketAddress().getAddress());
        final Address downstreamLocalAddress = properties.getDownstreamLocalAddress();
        final ServiceMetaInfo localService = find(downstreamLocalAddress.getSocketAddress().getAddress());

        ServiceMeshMetric.Builder metric = null;
        if (cluster.startsWith("inbound|")) {
            // Server side
            metric = adaptToDownstreamMetrics(entry)
                .setDestServiceName(localService.getServiceName())
                .setDestServiceInstance(localService.getServiceInstanceName())
                .setDetectPoint(DetectPoint.server);
            if (downstreamService.equals(ServiceMetaInfo.UNKNOWN)) {
                // Ingress -> sidecar(server side)
                // Mesh telemetry without source, the relation would be generated.

                log.debug("Transformed ingress->sidecar inbound mesh metric {}", metric);
            } else {
                // sidecar -> sidecar(server side)
                metric.setSourceServiceName(downstreamService.getServiceName())
                      .setSourceServiceInstance(downstreamService.getServiceInstanceName());

                log.debug("Transformed sidecar->sidecar(server side) inbound mesh metric {}", metric);
            }
        } else if (cluster.startsWith("outbound|")) {
            // sidecar(client side) -> sidecar
            Address upstreamRemoteAddress = properties.getUpstreamRemoteAddress();
            ServiceMetaInfo destService = find(upstreamRemoteAddress.getSocketAddress().getAddress());

            metric = adaptToDownstreamMetrics(entry)
                .setSourceServiceName(downstreamService.getServiceName())
                .setSourceServiceInstance(downstreamService.getServiceInstanceName())
                .setDestServiceName(destService.getServiceName())
                .setDestServiceInstance(destService.getServiceInstanceName())
                .setDetectPoint(DetectPoint.client);

            log.debug("Transformed sidecar->sidecar(server side) inbound mesh metric {}", metric);
        }

        Optional.ofNullable(metric).ifPresent(sources::add);

        return sources;
    }

    protected List<ServiceMeshMetric.Builder> analyzeProxy(final HTTPAccessLogEntry entry) {
        final AccessLogCommon properties = entry.getCommonProperties();
        if (properties == null) {
            return Collections.emptyList();
        }
        final Address downstreamLocalAddress = properties.getDownstreamLocalAddress();
        final Address downstreamRemoteAddress = properties.getDownstreamRemoteAddress();
        final Address upstreamRemoteAddress = properties.getUpstreamRemoteAddress();
        if (downstreamLocalAddress == null || downstreamRemoteAddress == null || upstreamRemoteAddress == null) {
            return Collections.emptyList();
        }

        List<ServiceMeshMetric.Builder> result = new ArrayList<>(2);
        SocketAddress downstreamRemoteAddressSocketAddress = downstreamRemoteAddress.getSocketAddress();
        ServiceMetaInfo outside = find(downstreamRemoteAddressSocketAddress.getAddress());

        SocketAddress downstreamLocalAddressSocketAddress = downstreamLocalAddress.getSocketAddress();
        ServiceMetaInfo ingress = find(downstreamLocalAddressSocketAddress.getAddress());

        ServiceMeshMetric.Builder metric = adaptToDownstreamMetrics(entry)
            .setSourceServiceName(outside.getServiceName())
            .setSourceServiceInstance(outside.getServiceInstanceName())
            .setDestServiceName(ingress.getServiceName())
            .setDestServiceInstance(ingress.getServiceInstanceName())
            .setDetectPoint(DetectPoint.server);

        log.debug("Transformed ingress inbound mesh metric {}", metric);
        result.add(metric);

        SocketAddress upstreamRemoteAddressSocketAddress = upstreamRemoteAddress.getSocketAddress();
        ServiceMetaInfo targetService = find(upstreamRemoteAddressSocketAddress.getAddress());

        ServiceMeshMetric.Builder outboundMetric = adaptUpstreamMetrics(entry)
            .setSourceServiceName(ingress.getServiceName())
            .setSourceServiceInstance(ingress.getServiceInstanceName())
            .setDestServiceName(targetService.getServiceName())
            .setDestServiceInstance(targetService.getServiceInstanceName())
            // Can't parse it from tls properties, leave it to Server side.
            .setTlsMode(NON_TLS)
            .setDetectPoint(DetectPoint.client);

        log.debug("Transformed ingress outbound mesh metric {}", outboundMetric);
        result.add(outboundMetric);

        return result;
    }

    /**
     * @return found service info, or {@link ServiceMetaInfo#UNKNOWN} to represent not found.
     */
    protected ServiceMetaInfo find(String ip) {
        return serviceRegistry.findService(ip);
    }
}
