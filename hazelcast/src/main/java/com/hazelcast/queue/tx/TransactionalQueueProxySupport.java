/*
 * Copyright (c) 2008-2012, Hazelcast, Inc. All Rights Reserved.
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

package com.hazelcast.queue.tx;

import com.hazelcast.nio.serialization.Data;
import com.hazelcast.queue.QueueItem;
import com.hazelcast.queue.QueueService;
import com.hazelcast.spi.AbstractDistributedObject;
import com.hazelcast.spi.Invocation;
import com.hazelcast.spi.NodeEngine;
import com.hazelcast.transaction.Transaction;
import com.hazelcast.transaction.TransactionalObject;
import com.hazelcast.util.ExceptionUtil;

import java.util.concurrent.Future;

/**
 * @ali 3/25/13
 */
public abstract class TransactionalQueueProxySupport extends AbstractDistributedObject<QueueService> implements TransactionalObject {

    protected final String name;
    protected final Transaction tx;
    protected final int partitionId;

    protected TransactionalQueueProxySupport(NodeEngine nodeEngine, QueueService service, String name, Transaction tx) {
        super(nodeEngine, service);
        this.name = name;
        this.tx = tx;
        partitionId = nodeEngine.getPartitionService().getPartitionId(name);
    }

    public boolean offerInternal(Data data, long timeout){
        throwExceptionIfNull(data);
        TxnReserveOfferOperation operation = new TxnReserveOfferOperation(name, timeout);
        try {
            Invocation invocation = getNodeEngine().getOperationService().createInvocationBuilder(QueueService.SERVICE_NAME, operation, partitionId).build();
            Future<Long> f = invocation.invoke();
            Long itemId = f.get();
            if (itemId != null){
                tx.addTransactionLog(new QueueTransactionLog(itemId, name, partitionId, new TxnOfferOperation(name, itemId, data)));
                return true;
            }
        } catch (Throwable t) {
            ExceptionUtil.rethrow(t);
        }
        return false;
    }

    public Data pollInternal(long timeout){
        TxnReservePollOperation operation = new TxnReservePollOperation(name, timeout);
        try {
            Invocation invocation = getNodeEngine().getOperationService().createInvocationBuilder(QueueService.SERVICE_NAME, operation, partitionId).build();
            Future<QueueItem> f = invocation.invoke();
            QueueItem item = f.get();
            if (item != null){
                tx.addTransactionLog(new QueueTransactionLog(item.getItemId(), name, partitionId, new TxnPollOperation(name, item.getItemId())));
                return item.getData();
            }
        } catch (Throwable t) {
            ExceptionUtil.rethrow(t);
        }
        return null;
    }

    public Object getId() {
        return name;
    }

    public String getName() {
        return name;
    }

    public final String getServiceName() {
        return QueueService.SERVICE_NAME;
    }

    private void throwExceptionIfNull(Object o){
        if (o == null){
            throw new NullPointerException("Object is null");
        }
    }
}