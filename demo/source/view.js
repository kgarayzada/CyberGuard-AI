// INTENTIONALLY VULNERABLE STATIC FIXTURE. Do not execute.
function showMessage(element, untrustedMessage) {
  element.innerHTML = untrustedMessage;
}
