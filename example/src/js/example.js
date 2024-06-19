import { JailbreakRootDetection } from 'jailbreak-root-detection';

window.testEcho = () => {
    const inputValue = document.getElementById("echoInput").value;
    JailbreakRootDetection.echo({ value: inputValue })
}
