package burp;

import javax.swing.text.Utilities;
import java.util.LinkedHashMap;
import java.util.Map;

// thanks stackoverflow
public class LimitedHashMap<K, V> extends LinkedHashMap<K, V> {
    private final int maxSize;

    public LimitedHashMap(int maxSize) {
        this.maxSize = maxSize;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        if (size() > maxSize) {
            System.out.println("Discarding old interaction");
        }
        return size() > maxSize;
    }
}
