package com.dyq.cipher.util;

import java.lang.reflect.Array;
/**
 * 数组工具类
 * @author xiaoming
 * 2017年2月4日
 */
public class ArrayUtils {
    public static byte[] subarray(final byte[] data, int startIndexInclusive, int endIndexExclusive) {

        if (data == null) {
            return null;
        }

        if (startIndexInclusive < 0) {
            startIndexInclusive = 0;
        }

        if (endIndexExclusive > data.length) {
            endIndexExclusive = data.length;
        }

        final int newSize = endIndexExclusive - startIndexInclusive;

        final Class<?> type = data.getClass().getComponentType();

        if (newSize <= 0) {

            @SuppressWarnings("unchecked") // OK, because array is of type T

            final byte[] emptyArray = (byte[]) Array.newInstance(type, 0);

            return emptyArray;

        }

        @SuppressWarnings("unchecked") // OK, because array is of type T
        final byte[] subarray = (byte[]) Array.newInstance(type, newSize);

        System.arraycopy(data, startIndexInclusive, subarray, 0, newSize);

        return subarray;
    }
    
    public static byte[] addAll(final byte[] enBytes, final byte... tmpData) {

        if (enBytes == null) {
            return clone(tmpData);
        } else if (tmpData == null) {
            return clone(enBytes);
        }

        final Class<?> type1 = enBytes.getClass().getComponentType();

        @SuppressWarnings("unchecked") // OK, because array is of type T
        final byte[] joinedArray = (byte[]) Array.newInstance(type1, enBytes.length + tmpData.length);
        System.arraycopy(enBytes, 0, joinedArray, 0, enBytes.length);
        try {
            System.arraycopy(tmpData, 0, joinedArray, enBytes.length, tmpData.length);
        } catch (final ArrayStoreException ase) {

            // Check if problem was due to incompatible types

            /*

             * We do this here, rather than before the copy because:

             * - it would be a wasted check most of the time

             * - safer, in case check turns out to be too strict

             */
            final Class<?> type2 = tmpData.getClass().getComponentType();

            if (!type1.isAssignableFrom(type2)){

                throw new IllegalArgumentException("Cannot store "+type2.getName()+" in an array of "
                        +type1.getName(), ase);
            }
            throw ase; // No, so rethrow original
        }
        return joinedArray;
    }
    
    public static byte[] clone(final byte[] enBytes) {
        if (enBytes == null) {
            return null;
        }
        return enBytes.clone();
    }
}
