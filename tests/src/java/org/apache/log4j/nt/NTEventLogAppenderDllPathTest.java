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
package org.apache.log4j.nt;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.StringTokenizer;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.log4j.LogManager;

/**
 * Tests of the NTEventLogAppender DLL path configuration
 * (sonatype-2010-0053, DLL preloading). Unlike {@link NTEventLogAppenderTest}
 * these tests do not need the NTEventLogAppender DLL and run on every platform.
 *
 * <p>Without a configured DLL path, {@link NTEventLogAppender} resolves its
 * native library with {@link System#loadLibrary(String)}, which searches the
 * library path (on Windows the current directory and the PATH), so a DLL
 * planted by an attacker in one of those directories gets loaded into the
 * JVM. When the <code>log4j.nteventlog.dll.path</code> system property names
 * an existing absolute file, that file is loaded with
 * {@link System#load(String)} and the library path is not searched.
 *
 * <p>The first test plants bogus "attacker" libraries, under every name the
 * appender searches for, in a directory on <code>java.library.path</code>
 * (provided by tests/build.xml), configures the property with the absolute
 * path of a genuine JDK native library and initializes the appender class.
 * Loading any planted library fails, so the class only initializes when the
 * configured absolute path is used and the planted libraries are ignored.
 * The remaining tests need the initialized appender class.
 */
public class NTEventLogAppenderDllPathTest extends TestCase {

  /**
   * System property naming the directory on java.library.path
   * in which the attacker libraries are planted.
   */
  static final String PLANT_DIR_PROPERTY = "log4j.test.nteventlog.plant.dir";

  /**
   * JDK native libraries without side effects that are not loaded by default.
   */
  private static final String[] JDK_LIBRARIES =
    new String[] { "jaas_unix", "jaas_nt", "npt" };

  private String originalDllPath;

  public NTEventLogAppenderDllPathTest(final String name) {
    super(name);
  }

  /**
   * Runs the test initializing the appender class first.
   */
  public static Test suite() {
    TestSuite suite = new TestSuite();
    suite.addTest(new NTEventLogAppenderDllPathTest(
        "testPlantedLibraryOnSearchPathIsNotLoaded"));
    suite.addTest(new NTEventLogAppenderDllPathTest(
        "testResolveConfiguredDllPath_notSet"));
    suite.addTest(new NTEventLogAppenderDllPathTest(
        "testResolveConfiguredDllPath_emptyString"));
    suite.addTest(new NTEventLogAppenderDllPathTest(
        "testResolveConfiguredDllPath_whitespaceOnly"));
    suite.addTest(new NTEventLogAppenderDllPathTest(
        "testResolveConfiguredDllPath_relativePath"));
    suite.addTest(new NTEventLogAppenderDllPathTest(
        "testResolveConfiguredDllPath_absoluteButMissing"));
    suite.addTest(new NTEventLogAppenderDllPathTest(
        "testResolveConfiguredDllPath_absoluteAndExists"));
    return suite;
  }

  public void setUp() {
    originalDllPath = System.getProperty(NTEventLogAppender.DLL_PATH_PROPERTY);
    System.getProperties().remove(NTEventLogAppender.DLL_PATH_PROPERTY);
  }

  public void tearDown() {
    if (originalDllPath != null) {
      System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, originalDllPath);
    } else {
      System.getProperties().remove(NTEventLogAppender.DLL_PATH_PROPERTY);
    }
    LogManager.shutdown();
  }

  /**
   * Plants attacker libraries on java.library.path, configures the absolute
   * path of a genuine library and checks that NTEventLogAppender is
   * initialized from the configured path instead of the planted libraries.
   */
  public void testPlantedLibraryOnSearchPathIsNotLoaded() throws Exception {
    String plantDirName = System.getProperty(PLANT_DIR_PROPERTY);
    assertNotNull("System property " + PLANT_DIR_PROPERTY + " is not set",
        plantDirName);
    File plantDir = new File(plantDirName).getAbsoluteFile();
    assertTrue(plantDir + " is not on java.library.path",
        isOnLibraryPath(plantDir));

    File configured = findJdkLibrary();
    assertNotNull("No JDK native library found on sun.boot.library.path",
        configured);

    File[] planted = plantLibraries(plantDir);
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY,
        configured.getAbsolutePath());
    try {
      Class.forName("org.apache.log4j.nt.NTEventLogAppender");
    } catch (UnsatisfiedLinkError e) {
      fail("NTEventLogAppender searched the library path and loaded a"
          + " planted library instead of " + configured + ": " + e.getMessage());
    } finally {
      for (int i = 0; i < planted.length; i++) {
        planted[i].delete();
      }
    }
  }

  /**
   * When the system property is not set, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_notSet() {
    System.getProperties().remove(NTEventLogAppender.DLL_PATH_PROPERTY);
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is an empty string, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_emptyString() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is whitespace only, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_whitespaceOnly() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "   ");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is a relative path, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_relativePath() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "relative/path/NTEventLogAppender.dll");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is an absolute path to a file that does not exist,
   * resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_absoluteButMissing() {
    String missingPath = new File(System.getProperty("java.io.tmpdir"), "no_such_NTEventLogAppender.dll")
        .getAbsolutePath();
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, missingPath);
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is an absolute path to an existing file,
   * resolveConfiguredDllPath should return that absolute path.
   */
  public void testResolveConfiguredDllPath_absoluteAndExists() throws IOException {
    File tempFile = File.createTempFile("NTEventLogAppender", ".dll");
    tempFile.deleteOnExit();
    try {
      String absolutePath = tempFile.getAbsolutePath();
      System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, absolutePath);
      String result = NTEventLogAppender.resolveConfiguredDllPath();
      assertNotNull(result);
      assertEquals(absolutePath, result);
    } finally {
      tempFile.delete();
    }
  }

  /**
   * Creates bogus libraries under every name searched for by the
   * NTEventLogAppender static initializer.
   */
  private static File[] plantLibraries(final File dir) throws IOException {
    String[] names = new String[] {
      System.mapLibraryName("NTEventLogAppender." + System.getProperty("os.arch")),
      System.mapLibraryName("NTEventLogAppender")
    };
    File[] planted = new File[names.length];
    for (int i = 0; i < names.length; i++) {
      planted[i] = new File(dir, names[i]);
      OutputStream os = new FileOutputStream(planted[i]);
      try {
        os.write("attacker controlled, not a native library".getBytes());
      } finally {
        os.close();
      }
    }
    return planted;
  }

  private static boolean isOnLibraryPath(final File dir) {
    StringTokenizer tokens = new StringTokenizer(
        System.getProperty("java.library.path", ""), File.pathSeparator);
    while (tokens.hasMoreTokens()) {
      if (dir.equals(new File(tokens.nextToken()).getAbsoluteFile())) {
        return true;
      }
    }
    return false;
  }

  private static File findJdkLibrary() {
    for (int i = 0; i < JDK_LIBRARIES.length; i++) {
      String name = System.mapLibraryName(JDK_LIBRARIES[i]);
      StringTokenizer tokens = new StringTokenizer(
          System.getProperty("sun.boot.library.path", ""), File.pathSeparator);
      while (tokens.hasMoreTokens()) {
        File candidate = new File(tokens.nextToken(), name).getAbsoluteFile();
        if (candidate.isFile()) {
          return candidate;
        }
      }
    }
    return null;
  }
}
