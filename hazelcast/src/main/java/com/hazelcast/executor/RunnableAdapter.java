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

package com.hazelcast.executor;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.HazelcastInstanceAware;
import com.hazelcast.nio.ObjectDataInput;
import com.hazelcast.nio.ObjectDataOutput;
import com.hazelcast.nio.serialization.DataSerializable;

import java.io.IOException;
import java.util.concurrent.Callable;

public class RunnableAdapter<V> implements DataSerializable, Callable<V>, HazelcastInstanceAware {

    private Runnable task;

    private V result;

    public RunnableAdapter() {
    }

    public RunnableAdapter(Runnable task) {
        this.task = task;
    }

    public RunnableAdapter(Runnable task, V result) {
        super();
        this.task = task;
        this.result = result;
    }

    public V getResult() {
        return result;
    }

    public Runnable getRunnable() {
        return task;
    }

    public void setRunnable(Runnable runnable) {
        task = runnable;
    }

    public V call() throws Exception {
        task.run();
        return result;
    }

    public final void setHazelcastInstance(HazelcastInstance hazelcastInstance) {
        if (task instanceof HazelcastInstanceAware) {
            ((HazelcastInstanceAware) task).setHazelcastInstance(hazelcastInstance);
        }
    }

    public void writeData(ObjectDataOutput out) throws IOException {
        out.writeObject(task);
    }

    public void readData(ObjectDataInput in) throws IOException {
        task = in.readObject();
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("RunnableAdapter");
        sb.append("{task=").append(task);
        sb.append('}');
        return sb.toString();
    }
}