/*
 * Copyright (c) 2018 LingoChamp Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.liulishuo.okdownload.core.breakpoint;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.SparseArray;

import com.liulishuo.okdownload.DownloadTask;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;

public class KeyToIdMap {

    @SuppressWarnings("PMD.AvoidFieldNameMatchingTypeName")
    @NonNull
    private final HashMap<String, Integer> keyToIdMap;
    @NonNull
    private final SparseArray<String> idToKeyMap;

    KeyToIdMap() {
        this(new HashMap<String, Integer>(), new SparseArray<String>());
    }

    KeyToIdMap(@NonNull HashMap<String, Integer> keyToIdMap,
               @NonNull SparseArray<String> idToKeyMap) {
        this.keyToIdMap = keyToIdMap;
        this.idToKeyMap = idToKeyMap;
    }

    @Nullable
    public Integer get(@NonNull DownloadTask task) {
        final Integer candidate = keyToIdMap.get(generateKey(task));
        if (candidate != null) return candidate;
        return null;
    }

    public void remove(int id) {
        final String key = idToKeyMap.get(id);
        if (key != null) {
            keyToIdMap.remove(key);
            idToKeyMap.remove(id);
        }
    }

    public void add(@NonNull DownloadTask task, int id) {
        final String key = generateKey(task);
        keyToIdMap.put(key, id);
        idToKeyMap.put(id, key);
    }

    String generateKey(@NonNull DownloadTask task) {
        return task.getUrl() + task.getUri() + task.getFilename();
    }

    public static String formatString(final String msg, Object... args) {
        return String.format(Locale.ENGLISH, msg, args);
    }


    /**
     * @param url  The downloading URL.
     * @param path The absolute file path.
     * @return The download id.
     */
    public static int generateId(final String url, final String path) {
        return generateId(url, path, false);
    }

    /**
     * @param url  The downloading URL.
     * @param path If {@code pathAsDirectory} is {@code true}, {@code path} would be the absolute
     *             directory to place the file;
     *             If {@code pathAsDirectory} is {@code false}, {@code path} would be the absolute
     *             file path.
     * @return The download id.
     */
    public static int generateId(final String url, final String path, final boolean pathAsDirectory) {
        if (pathAsDirectory) {
            return md5(formatString("%sp%s@dir", url, path)).hashCode();
        } else {
            return md5(formatString("%sp%s", url, path)).hashCode();
        }
    }

    private static String md5(String string) {
        byte[] hash;
        try {
            hash = MessageDigest.getInstance("MD5").digest(string.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Huh, MD5 should be supported?", e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Huh, UTF-8 should be supported?", e);
        }

        StringBuilder hex = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            if ((b & 0xFF) < 0x10) hex.append("0");
            hex.append(Integer.toHexString(b & 0xFF));
        }
        return hex.toString();
    }
}
