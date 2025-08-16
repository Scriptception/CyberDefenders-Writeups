# FakeGPT

## Scenario
Your cybersecurity team has been alerted to suspicious activity on your organization's network. Several employees reported unusual behavior in their browsers after installing what they believed to be a helpful browser extension named "ChatGPT". However, strange things started happening: accounts were being compromised, and sensitive information appeared to be leaking.

Your task is to perform a thorough analysis of this extension identify its malicious components.

## Questions


### 1. Which encoding method does the browser extension use to obscure target URLs, making them more difficult to detect during analysis?

We are given a copy of this Chrome extension to analyse.

The main file is the `app.js`, which we can read through to see that it's a keylogger:

```js
document.addEventListener('keydown', function(event) {
            var key = event.key;
            exfiltrateData('keystroke', key);
        });
```

Below, we can also see that it's using `CryptoJS` to encrypt the payload, specifically by Base64 encoding the data.

This is our answer: `base64`


### 2. Which website does the extension monitor for data theft, targeting user accounts to steal sensitive information?

We see a B64 encoding `targets` array: `d3d3LmZhY2Vib29rLmNvbQ==`.

This var is used in the next line, to match against the site visited in the browser.

Decoding this: `echo -n "d3d3LmZhY2Vib29rLmNvbQ==" | base64 -d`, we get `www.facebook.com`


### 3. Which type of HTML element is utilized by the extension to send stolen data?

In the `sendToServer` function, we see it creating an image with the source of the C2 server with the payload as a URL param.

The `<img>` HTML element is used.

### 4. What is the first specific condition in the code that triggers the extension to deactivate itself?

In the `loader.js`, we see it runs a somewhat poor check to tell if the extension is being loaded in a virtual environment.

The first of these checks is: `navigator.plugins.length === 0`

### 5. Which event does the extension capture to track user input submitted through forms?

This is just a basic JS question, and we see in `app.js` that it's adding an event listener on the `submit` event.

The `submit` event is used when you submit form data, such as username and password fields.

### 6. Which API or method does the extension use to capture and monitor user keystrokes?

Similar to the previous question, we see a `keydown` listener created in `app.js` which gets triggered, as the name suggests, when a key is pressed.

We can see that they are capturing the pressed keys as `var key`

### 7. What is the domain where the extension transmits the exfiltrated data?

We saw this domain earlier when inspecting the method of exfil: `Mo[.]Elshaheedy[.]com`

### 8. Which function in the code is used to exfiltrate user credentials, including the username and password?

`exfiltrateCredentials(username, password);`

### 9. Which encryption algorithm is applied to secure the data before sending?

`AES`, as seen in the line: `const encrypted = CryptoJS.AES.encrypt(data, key, { iv: iv });`

### 10. What does the extension access to store or manipulate session-related data and authentication information?

In the `manifest.json`, we can read the list of permissions 'required' by the extension. The one relating to this question is `cookies`
