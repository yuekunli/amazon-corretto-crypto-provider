// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import java.security.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_PROVIDER, mode = ResourceAccessMode.READ_WRITE)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class SecurityManagerTest {
  private AtomicReference<Thread> threadToDeny = new AtomicReference<>(null);

  @BeforeEach
  public void priv_setUp() throws Exception {
    // JCE requires permissions to do some initialization work (e.g. reading jurisdictional
    // permissions). Let this
    // init happen by doing some dummy cipher work with the built-in JCE providers first.
    Security.removeProvider("AmazonCorrettoCryptoProvider");
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));
    c.doFinal();

    // test case "sanityCheck_securityManager_doesDeny" triggers the initialization <clinit> of TestUtil class.
    // and this requires a bunch of permission checks. Invoke something on TestUtil so that its members are initialized.
    System.out.println(TestUtil.isFips());


    Security.insertProviderAt(AmazonCorrettoCryptoProvider.INSTANCE, 1);
    System.setSecurityManager(new OneThreadSecurityManager(threadToDeny));
  }

  @AfterEach
  public void priv_tearDown() throws Exception {
    threadToDeny.set(null);

    System.setSecurityManager(null);

    Security.removeProvider("AmazonCorrettoCryptoProvider");
    threadToDeny = null;
  }

  private static final class CallExpectedToFail implements ThrowingRunnable {

    @Override
    public void run() throws Throwable {
      Object.class.getDeclaredMethod("clone").setAccessible(true);
    }
  }

  @Test
  public void sanityCheck_securityManager_doesDeny() throws Exception {
    try {
      CallExpectedToFail call = new CallExpectedToFail();
      threadToDeny.set(Thread.currentThread());

      // C:\Users\YuekunLi\.jdks\corretto-1.8.0_402\src.zip!\java\lang\reflect\AccessibleObject.java
      // the comments of "setAccessible" claim that a ReflectPermission("suppressAccessChecks") is checked
      // when "setAccessible" is called. So if I don't grant that permission, the "CallExpectedToFail" should
      // fail because of "suppressAccessChecks" permission is denied. But in fact, it fails on
      // access denied ("java.lang.RuntimePermission" "accessDeclaredMembers").
      // Actually "accessDeclaredmembers" sounds to make more sense because "CallExpectedToFail" essentially
      // accesses the member function "clone".
      assertThrows(SecurityException.class, call);
    } finally {
      threadToDeny.set(null);
    }
  }

  @Test
  public void testDigestsUnderSecurityManager() throws Exception {
    try {
      threadToDeny.set(Thread.currentThread());

      MessageDigest.getInstance("SHA-1").digest(new byte[10]);

      MessageDigest md = MessageDigest.getInstance("SHA-1");
      assertEquals("AmazonCorrettoCryptoProvider", md.getProvider().getName());

      md.update(new byte[10]);
      md.digest(new byte[10]);
    } finally {
      threadToDeny.set(null);
    }
  }

  @Test
  public void testAESUnderSecurityManager() throws Exception {
    try {
      threadToDeny.set(Thread.currentThread());

      Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "AmazonCorrettoCryptoProvider");
      assertEquals("AmazonCorrettoCryptoProvider", c.getProvider().getName());

      c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));
      c.update(new byte[10]);
      c.doFinal();
    } finally {
      threadToDeny.set(null);
    }
  }

  private static class OneThreadSecurityManager extends SecurityManager {
    private final AtomicReference<Thread> threadToDeny;

    private OneThreadSecurityManager(AtomicReference<Thread> threadToDeny) {
      this.threadToDeny = threadToDeny;
    }

    @Override
    public void checkPermission(Permission perm) {
      if (Thread.currentThread() != threadToDeny.get())
        return;

      //Thread oldThread = null;
      try {
        AccessController.checkPermission(perm);
        System.out.println(perm);
      } catch (SecurityException e) {
        //oldThread = threadToDeny.getAndSet(null);

        e.printStackTrace();

        throw e;
      } //finally {
        //threadToDeny.set(oldThread);
      //}
    }
  }
}