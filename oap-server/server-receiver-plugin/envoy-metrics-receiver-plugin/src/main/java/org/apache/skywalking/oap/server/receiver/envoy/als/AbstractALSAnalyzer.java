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

import io.envoyproxy.envoy.api.v2.core.Node;
import io.envoyproxy.envoy.service.accesslog.v2.StreamAccessLogsMessage;

public abstract class AbstractALSAnalyzer implements ALSHTTPAnalysis {

    @Override
    public Role identify(final StreamAccessLogsMessage.Identifier alsIdentifier, final Role defaultRole) {
        if (alsIdentifier == null) {
            return defaultRole;
        }
        final Node node = alsIdentifier.getNode();
        if (node == null) {
            return defaultRole;
        }
        final String id = node.getId();
        if (id.startsWith("router~")) {
            return Role.PROXY;
        } else if (id.startsWith("sidecar~")) {
            return Role.SIDECAR;
        }
        return defaultRole;
    }

}
