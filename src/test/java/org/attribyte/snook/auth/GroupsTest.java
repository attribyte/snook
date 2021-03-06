/*
 * Copyright 2018 Attribyte, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.attribyte.snook.auth;

import com.google.common.collect.ImmutableList;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class GroupsTest {

   @Test
   public void validNoProperties() throws IOException {
      String line = "tester:group0:r";
      List<GroupProfile> profiles = Groups.parse(ImmutableList.of(line));
      assertNotNull(profiles);
      assertEquals(1, profiles.size());
      GroupProfile profile = profiles.get(0);
      assertEquals("tester", profile.username);
      assertEquals("group0", profile.groupName);
      assertTrue(profile.hasReadPermission());
      assertFalse(profile.hasWritePermission());
      assertTrue(profile.enabled);
      assertTrue(profile.properties.isEmpty());
   }

   @Test
   public void validDisabled() throws IOException {
      String line = "!tester:group0:r";
      List<GroupProfile> profiles = Groups.parse(ImmutableList.of(line));
      assertNotNull(profiles);
      assertEquals(1, profiles.size());
      GroupProfile profile = profiles.get(0);
      assertEquals("tester", profile.username);
      assertEquals("group0", profile.groupName);
      assertFalse(profile.enabled);
      assertTrue(profile.hasReadPermission());
      assertFalse(profile.hasWritePermission());
      assertTrue(profile.properties.isEmpty());
      assertEquals("r", Permission.setToString(profile.permissions));
   }

   @Test
   public void validEmptyGroup() throws IOException {
      String line = "tester::r";
      List<GroupProfile> profiles = Groups.parse(ImmutableList.of(line));
      assertNotNull(profiles);
      assertEquals(1, profiles.size());
      GroupProfile profile = profiles.get(0);
      assertEquals("tester", profile.username);
      assertEquals("", profile.groupName);
      assertEquals("Default", profile.getDisplayName());
      assertTrue(profile.hasReadPermission());
      assertFalse(profile.hasWritePermission());
      assertTrue(profile.properties.isEmpty());
   }

   @Test
   public void validMultiGroups() throws IOException {
      String line = "tester:group0,group1:r";
      List<GroupProfile> profiles = Groups.parse(ImmutableList.of(line));
      assertNotNull(profiles);
      assertEquals(2, profiles.size());
      GroupProfile profile0 = profiles.get(0);
      assertEquals("tester", profile0.username);
      assertEquals("group0", profile0.groupName);
      assertTrue(profile0.hasReadPermission());
      assertFalse(profile0.hasWritePermission());
      assertTrue(profile0.properties.isEmpty());
      GroupProfile profile1 = profiles.get(1);
      assertEquals("tester", profile1.username);
      assertEquals("group1", profile1.groupName);
      assertTrue(profile1.hasReadPermission());
      assertFalse(profile1.hasWritePermission());
      assertTrue(profile1.properties.isEmpty());
   }


   @Test
   public void validGlobal() throws IOException {
      String line = "tester:*:rw:{}";
      List<GroupProfile> profiles = Groups.parse(ImmutableList.of(line));
      assertNotNull(profiles);
      assertEquals(1, profiles.size());
      GroupProfile profile = profiles.get(0);
      assertEquals("tester", profile.username);
      assertEquals("*", profile.groupName);
      assertTrue(profile.hasGlobalReadPermission());
      assertTrue(profile.hasGlobalWritePermission());
      assertTrue(profile.hasReadPermission());
      assertTrue(profile.hasWritePermission());
      assertTrue(profile.properties.isEmpty());
      assertEquals("rw", Permission.setToString(profile.permissions));

   }

   @Test
   public void validWithProperties() throws IOException {
      String line = "tester:group0:rw:{prop0:prop0val, 'prop1':'prop1,val'}";
      List<GroupProfile> profiles = Groups.parse(ImmutableList.of(line));
      assertNotNull(profiles);
      assertEquals(1, profiles.size());
      GroupProfile profile = profiles.get(0);
      assertEquals("tester", profile.username);
      assertEquals("group0", profile.groupName);
      assertTrue(profile.hasReadPermission());
      assertTrue(profile.hasWritePermission());
      assertEquals(2, profile.properties.size());
      assertEquals("prop0val", profile.properties.getOrDefault("prop0", ""));
      assertEquals("prop1,val", profile.properties.getOrDefault("prop1", ""));
      System.out.println(Groups.toLine(profile));
   }

   @Test(expected = IOException.class)
   public void invalidWithProperties() throws IOException {
      String line = "tester:group0:rw:{prop0='prop0val', 'prop1'='prop1val'";
      List<GroupProfile> profiles = Groups.parse(ImmutableList.of(line));
      assertNotNull(profiles);
      assertEquals(1, profiles.size());
      GroupProfile profile = profiles.get(0);
      System.out.println(profile.toString());
   }
}
