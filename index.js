;(function () {
  "use strict";

  /**
  * Constants.
  */

  var webCrypto = window.crypto || window.msCrypto || window.webkitCrypto || window.mozCrypto
  var pbkdf2Salt = new Uint8Array(
    [8, 197, 37, 195, 28, 68, 95, 244, 172, 120, 36, 13, 17, 99, 142, 245]
  )
  var pbkdf2Iterations = 10000
  var cypherSeparator = '_'
  var emailAddress = 'ealmansi@gmail.com'
  var baseUrl = 'https://nimblesecrets.xyz'

  /**
  * Array utilities.
  */

  function arrayBufferToBase64 (arrayBuffer) {
    var array = new Uint8Array(arrayBuffer)
    var data = ''
    for (var i = 0; i < array.byteLength; ++i) {
      data += String.fromCharCode(array[i])
    }
    return window.btoa(data)
  }

  function base64ToArrayBuffer (base64) {
    var data = window.atob(base64)
    var array = new Uint8Array(data.length)
    for (var i = 0; i < data.length; ++i) {
      array[i] = data.charCodeAt(i)
    }
    return array.buffer
  }

  function stringToArrayBuffer (string) {
    var utf8 = unescape(encodeURIComponent(string))
    var array = []
    for (var i = 0; i < utf8.length; ++i) {
      array.push(utf8.charCodeAt(i))
    }
    return new Uint8Array(array).buffer
  }

  function arrayBufferToString (arrayBuffer) {
    var utf8 = String.fromCharCode.apply(null, new Uint8Array(arrayBuffer))
    return decodeURIComponent(escape(utf8))
  }

  /**
  * Crypto.
  */

  function encode (plaintext, password) {
    try {
      return Promise.resolve().then(
        function () {
          return deriveKey(password)
        }
      ).then(
        function (key) {
          var iv = window.crypto.getRandomValues(new Uint8Array(16))
          return Promise.all([
            Promise.resolve(iv),
            window.crypto.subtle.encrypt(
              {
                name: 'AES-CBC',
                iv
              },
              key,
              stringToArrayBuffer(plaintext)
            )
          ])
        }
      ).then(
        function (values) {
          var iv = values[0]
          var cyphertext = values[1]
          return arrayBufferToBase64(iv) + cypherSeparator + arrayBufferToBase64(cyphertext)
        }
      )
    } catch (err) {
      return Promise.reject(err)
    }
  }

  function decode (cypher, password) {
    try {
      var iv = base64ToArrayBuffer(cypher.substr(0, cypher.indexOf(cypherSeparator)))
      var cyphertext = base64ToArrayBuffer(cypher.substr(cypher.indexOf(cypherSeparator) + 1))
      return Promise.resolve().then(
        function () {
          return deriveKey(password)
        }
      ).then(
        function (key) {
          return webCrypto.subtle.decrypt(
            {
              name: 'AES-CBC',
              iv
            },
            key,
            cyphertext
          )
        }
      ).then(
        function (plaintextArrayBuffer) {
          return arrayBufferToString(plaintextArrayBuffer)
        }
      )
    } catch (err) {
      return Promise.reject(err)
    }
  }

  function deriveKey (password) {
    return Promise.resolve().then(
      function () {
        return webCrypto.subtle.importKey(
          'raw',
          stringToArrayBuffer(password),
          { name: 'PBKDF2' },
          false,
          ['deriveKey', 'deriveBits']
        )
      }
    ).then(
      function (key) {
        return webCrypto.subtle.deriveBits(
          {
            name: 'PBKDF2',
            salt: pbkdf2Salt,
            iterations: pbkdf2Iterations,
            hash: { name: 'SHA-256' }
          },
          key,
          256 
        )
      }
    ).then(
      function (bits) {
        return webCrypto.subtle.importKey(
          'raw',
          bits,
          {
            name: 'AES-CBC'
          },
          false,
          ['encrypt', 'decrypt']
        )
      }
    )
  }

  /**
  * DOM.
  */

  function main () {
    var query = parseQuery(location.search)
    if (query['cypher'] !== undefined) {
      var cypherInput = document.getElementById('cypher')
      cypherInput.value = query['cypher']
    }
    if (query['title'] !== undefined) {
      var titleInput = document.getElementById('title')
      titleInput.value = query['title']
    }
    var encodeButton = document.getElementById('encode-button')
    encodeButton.addEventListener('click', onEncode)
    var decodeButton = document.getElementById('decode-button')
    decodeButton.addEventListener('click', onDecode)
    var clearButton = document.getElementById('clear-button')
    clearButton.addEventListener('click', onClear)
  }

  function parseQuery (queryString) {
    var query = {}
    if (typeof queryString === 'string' && queryString.startsWith('?')) {
      var pairs = queryString.substr(1).split('&')
      for (var i = 0; i < pairs.length; ++i) {
        var keyValue = pairs[i].split('=')
        query[keyValue[0]] = decodeURIComponent(keyValue[1])
      }
    }
    return query
  }

  function buildQueryString (query) {
    var queryString = ''
    for (var key in query) {
      queryString += queryString.length === 0 ? '?' : '&'
      queryString += key + '=' + encodeURIComponent(query[key])
    }
    return queryString
  }

  function onEncode () {
    var title = document.getElementById('title').value
    var plaintext = document.getElementById('plaintext').value
    var password = document.getElementById('password').value
    var repeatPassword = document.getElementById('repeat-password').value
    if (
      title.length === 0 ||
      plaintext.length === 0 ||
      password.length === 0 ||
      repeatPassword.length === 0
    ) {
      onError(new Error('Missing title, plaintext or password.'))
      return
    }
    if (password !== repeatPassword) {
      onError(new Error('Passwords don\'t match.'))
      return
    }
    encode(plaintext, password).then(
      function (cypher) {
        onEncodeSuccess(title, cypher)
      }
    ).catch(
      onError
    )
  }

  function onEncodeSuccess (title, cypher) {
    var plaintextTextArea = document.getElementById('plaintext')
    plaintextTextArea.value = ''
    var passwordInput = document.getElementById('password')
    passwordInput.value = ''
    var repeatPasswordInput = document.getElementById('repeat-password')
    repeatPasswordInput.value = ''
    var cypherInput = document.getElementById('cypher')
    cypherInput.value = cypher
    var subject = 'Nimble Secrets: ' + title
    var decodeLink = baseUrl + buildQueryString({ title: title, cypher: cypher })
    var body = 'Title: ' + title + '\n' + 'Cypher: ' + cypher + '\n' + 'Decode link: ' + decodeLink
    var href = 'mailto:' + emailAddress + buildQueryString({ subject: subject, body: body })
    var saveAnchor = document.getElementById('save')
    saveAnchor.href = href
  }

  function onDecode () {
    var cypher = document.getElementById('cypher').value
    var password = document.getElementById('password').value
    if (
      cypher.length === 0 ||
      password.length === 0
    ) {
      onError(new Error('Missing cypher or password.'))
      return
    }
    decode(cypher, password).then(
      onDecodeSuccess
    ).catch(
      onError
    )
  }

  function onDecodeSuccess (plaintext) {
    var plaintextTextArea = document.getElementById('plaintext')
    plaintextTextArea.value = plaintext
    var passwordInput = document.getElementById('password')
    passwordInput.value = ''
    var repeatPasswordInput = document.getElementById('repeat-password')
    repeatPasswordInput.value = ''
    var cypherInput = document.getElementById('cypher')
    cypherInput.value = ''
  }

  function onError (err) {
    alert(err.message || err.name || 'Unexpected error.')
  }

  function onClear () {
    var titleInput = document.getElementById('title')
    titleInput.value = ''
    var plaintextTextArea = document.getElementById('plaintext')
    plaintextTextArea.value = ''
    var passwordInput = document.getElementById('password')
    passwordInput.value = ''
    var repeatPasswordInput = document.getElementById('repeat-password')
    repeatPasswordInput.value = ''
    var cypherInput = document.getElementById('cypher')
    cypherInput.value = ''
  }
  
  main()
  
})()
