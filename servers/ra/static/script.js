function onScanSuccess(decodedText, decodedResult) {
  // handle the scanned code  
  document.getElementById('results').style.visibility = 'visible';
  document.getElementById('results').innerHTML = `Results: ${decodedText}`
  document.getElementById('scanButton').style.visibility = 'visible';

  // extract UIN
  const data = JSON.parse(decodedText)
  let uin = data["subject"]["UIN"];
  
  fetch('/verify-qr/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrftoken,
    },
    body: JSON.stringify({ UIN: uin }),
  }).then(response => response.json())
  .then(data => {
    if (data.status === "ok") {
      window.location.href = data.redirect
    } else {
      console.error("Invalid UIN")
    }
  });

  html5QrcodeScanner.clear()
}

function onScanFailure(error) {
  // handle scan failure, usually better to ignore and keep scanning.
  // for example:
  // console.warn(`Code scan error = ${error}`);
}

function startScan() {
  html5QrcodeScanner.render(onScanSuccess, onScanFailure);
  document.getElementById('scanButton').style.visibility = 'hidden';
}

function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      // Does this cookie string begin with the name we want?
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

let html5QrcodeScanner = new Html5QrcodeScanner(
  "reader",
  { fps: 10, qrbox: {width: 300, height: 300} },
  /* verbose= */ false);

const csrftoken = getCookie('csrftoken');