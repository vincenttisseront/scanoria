// Banc d'essai reach-index : SnakeYAML est importé et instancié.
import org.yaml.snakeyaml.Yaml;

public class App {
    public static Object read(String data) {
        return new Yaml().load(data);
    }
}
