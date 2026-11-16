/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests that the socket receivers only deserialize the classes making up a
 * {@link LoggingEvent} (CVE-2019-17571).
 */
public class HardenedLoggingEventInputStreamTest extends TestCase {

  static final String MDC_KEY = "hardenedTestKey";
  static final String MDC_PAYLOAD_KEY = "hardenedTestPayload";

  /**
   * Serializable class that records whether it was ever deserialized.
   * Stands in for a deserialization gadget.
   */
  static final class Gadget implements Serializable {
    private static final long serialVersionUID = 1L;
    static volatile boolean deserialized = false;

    private void readObject(final ObjectInputStream in)
      throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      deserialized = true;
    }
  }

  public HardenedLoggingEventInputStreamTest(final String name) {
    super(name);
  }

  public void setUp() {
    Gadget.deserialized = false;
  }

  public void tearDown() {
    MDC.remove(MDC_KEY);
    MDC.remove(MDC_PAYLOAD_KEY);
    Gadget.deserialized = false;
  }

  private static byte[] serialize(final Object o) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(bos);
    oos.writeObject(o);
    oos.flush();
    oos.close();
    return bos.toByteArray();
  }

  private static Object deserialize(final byte[] bytes)
    throws IOException, ClassNotFoundException {
    HardenedLoggingEventInputStream ois =
      new HardenedLoggingEventInputStream(new ByteArrayInputStream(bytes));
    try {
      return ois.readObject();
    } finally {
      ois.close();
    }
  }

  private static void assertRejected(final InvalidClassException ex,
                                     final String className) {
    String msg = ex.getMessage();
    assertTrue("unexpected message: " + msg,
               msg != null && msg.indexOf(className) != -1);
  }

  private static LoggingEvent createEvent(final String message,
                                          final Throwable t) {
    Logger logger = Logger.getLogger(HardenedLoggingEventInputStreamTest.class);
    return new LoggingEvent(Logger.class.getName(), logger, Level.INFO,
                            message, t);
  }

  /**
   * A regular logging event, including MDC, NDC, location and throwable
   * information, must still be accepted.
   */
  public void testLoggingEventIsAccepted() throws Exception {
    MDC.put(MDC_KEY, "mdcValue");
    LoggingEvent event = createEvent("Hello, world.", new Exception("Don't panic"));
    event.getLocationInformation();
    byte[] bytes;
    NDC.push("ndcValue");
    try {
      bytes = serialize(event);
    } finally {
      NDC.pop();
    }

    LoggingEvent copy = (LoggingEvent) deserialize(bytes);

    assertEquals(event.getLoggerName(), copy.getLoggerName());
    assertEquals(Level.INFO, copy.getLevel());
    assertEquals("Hello, world.", copy.getRenderedMessage());
    assertTrue(copy.getNDC().endsWith("ndcValue"));
    assertEquals(event.getNDC(), copy.getNDC());
    assertEquals("mdcValue", copy.getMDC(MDC_KEY));
    assertEquals(event.getThrowableStrRep()[0], copy.getThrowableStrRep()[0]);
    assertEquals(event.getLocationInformation().fullInfo,
                 copy.getLocationInformation().fullInfo);
  }

  /**
   * An arbitrary serializable object must be rejected before its
   * readObject method gets a chance to run.
   */
  public void testBadPayloadIsRejected() throws Exception {
    byte[] bytes = serialize(new BadPayload("x"));
    try {
      deserialize(bytes);
      fail("BadPayload should not have been deserialized");
    } catch (InvalidClassException ex) {
      assertRejected(ex, BadPayload.class.getName());
    }
  }

  /**
   * Arrays of unauthorized classes must be rejected as well.
   */
  public void testArrayOfBadPayloadIsRejected() throws Exception {
    byte[] bytes = serialize(new BadPayload[] { new BadPayload("x") });
    try {
      deserialize(bytes);
      fail("BadPayload[] should not have been deserialized");
    } catch (InvalidClassException ex) {
      assertRejected(ex, "[L" + BadPayload.class.getName() + ";");
    }
  }

  /**
   * MDC values travel as is inside a logging event; an unauthorized class
   * nested in the MDC must be rejected.
   */
  public void testGadgetInsideMDCIsRejected() throws Exception {
    MDC.put(MDC_PAYLOAD_KEY, new Gadget());
    byte[] bytes = serialize(createEvent("hello", null));
    try {
      deserialize(bytes);
      fail("Gadget nested in MDC should not have been deserialized");
    } catch (InvalidClassException ex) {
      assertRejected(ex, Gadget.class.getName());
    }
    assertFalse(Gadget.deserialized);
  }

  /**
   * Classes explicitly added to the whitelist are accepted.
   */
  public void testAdditionalAuthorizedClassIsAccepted() throws Exception {
    List additional = new ArrayList();
    additional.add(Gadget.class.getName());
    HardenedLoggingEventInputStream ois =
      new HardenedLoggingEventInputStream(
        new ByteArrayInputStream(serialize(new Gadget())), additional);
    try {
      assertTrue(ois.readObject() instanceof Gadget);
    } finally {
      ois.close();
    }
    assertTrue(Gadget.deserialized);
  }

  /**
   * Sends the given objects to a SocketNode over a real socket and lets the
   * node process them.
   */
  private static VectorAppender sendToSocketNode(final Object[] objects)
    throws Exception {
    Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
    VectorAppender appender = new VectorAppender();
    hierarchy.getRootLogger().addAppender(appender);

    ServerSocket serverSocket = new ServerSocket(0);
    try {
      Socket client = new Socket("localhost", serverSocket.getLocalPort());
      Socket accepted = serverSocket.accept();

      // Everything is written and the client side closed before the node
      // starts reading, so that SocketNode.run() returns on its own.
      ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
      try {
        for (int i = 0; i < objects.length; i++) {
          oos.writeObject(objects[i]);
        }
        oos.flush();
      } finally {
        oos.close();
        client.close();
      }

      SocketNode node = new SocketNode(accepted, hierarchy);
      node.run();
    } finally {
      serverSocket.close();
    }
    return appender;
  }

  /**
   * A gadget sent directly to a SocketNode must never be deserialized.
   */
  public void testSocketNodeRejectsGadget() throws Exception {
    VectorAppender appender =
      sendToSocketNode(new Object[] { createEvent("legit", null), new Gadget() });
    assertFalse("SocketNode deserialized an unauthorized class",
                Gadget.deserialized);
    assertEquals(1, appender.getVector().size());
    LoggingEvent received = (LoggingEvent) appender.getVector().elementAt(0);
    assertEquals("legit", received.getRenderedMessage());
  }

  /**
   * A gadget smuggled in the MDC of a logging event must never be
   * deserialized by SocketNode, while regular events are still logged.
   */
  public void testSocketNodeRejectsGadgetInsideMDC() throws Exception {
    LoggingEvent legit = createEvent("legit", null);
    legit.getMDCCopy();
    MDC.put(MDC_PAYLOAD_KEY, new Gadget());
    LoggingEvent malicious = createEvent("malicious", null);
    malicious.getMDCCopy();

    VectorAppender appender =
      sendToSocketNode(new Object[] { legit, malicious });
    assertFalse("SocketNode deserialized an unauthorized class",
                Gadget.deserialized);
    assertEquals(1, appender.getVector().size());
    LoggingEvent received = (LoggingEvent) appender.getVector().elementAt(0);
    assertEquals("legit", received.getRenderedMessage());
  }
}
