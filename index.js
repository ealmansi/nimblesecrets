/**
* Constants.
*/

var webCrypto = window.crypto || window.msCrypto || window.webkitCrypto || window.mozCrypto
var pbkdf2Salt = new Uint8Array([
  60, 241, 28, 16,
  233, 47, 220, 189,
  115, 206, 149, 109,
  40, 251, 155, 67
])
var pbkdf2Iterations = 10000
var cypherSeparator = '_'
var emailAddress = 'ealmansi@gmail.com'
var baseUrl = location.protocol + '//' + location.host

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

/**
* DOM.
*/

function onError (err) {
  alert(err.message)
}

function onDecodeSuccess (plaintext) {
  var textArea = document.getElementsByTagName('textarea').item(0)
  textArea.value = plaintext
}

function onDecodeFormSubmit (event) {
  event.preventDefault()
  var formData = new FormData(event.target)
  var cypher = formData.get('cypher')
  var password = formData.get('password')
  decode(cypher, password).then(onDecodeSuccess).catch(onError)
}

function onEncodeSuccess (title, cypher) {
  var subject = 'Nimble Secrets: ' + title
  var decodeLink = baseUrl + '?cypher=' + window.encodeURIComponent(cypher)
  var body = 'Title: ' + title + '\n' + 'Cypher: ' + cypher + '\n' + 'Decode: ' + decodeLink
  var href = 'mailto:' + emailAddress
  href = href + '?subject=' + window.encodeURIComponent(subject)
  href = href + '&body=' + window.encodeURIComponent(body)
  window.open(href)
}

function onEncodeFormSubmit (event) {
  event.preventDefault()
  var formData = new FormData(event.target)
  var title = formData.get('title')
  var plaintext = formData.get('plaintext')
  var password = formData.get('password')
  encode(plaintext, password).then(
    function (cypher) {
      onEncodeSuccess(title, cypher)
    }
  ).catch(onError)
}

function main () {
  if (location.search.startsWith('?cypher=')) {
    var input = document.getElementsByName('cypher').item(0)
    var cypher = window.decodeURIComponent(location.search.substr('?cypher='.length))
    input.value = cypher
  }
  var decodeForm = document.getElementById('decode-form')
  decodeForm.addEventListener('submit', onDecodeFormSubmit)
  var encodeForm = document.getElementById('encode-form')
  encodeForm.addEventListener('submit', onEncodeFormSubmit)
}

main()
