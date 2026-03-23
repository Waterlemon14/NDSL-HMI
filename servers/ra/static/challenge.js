function startChallenge() {
  const holder = document.getElementById('data-holder');
  const deviceID = holder.dataset.deviceid;
  document.getElementById('start-challenge').style.visibility = 'hidden';
  fetch(`/start-challenge/${deviceID}/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrftoken
    },
    body: JSON.stringify({ action: 'start' })
  }).then(response => response.json())
  .then(data => {
    if (data.status === "ok") {
      console.log("Starting challenge");
      let timer = data.interval;
      let count = data.count;
      console.log(timer);

      const countdown = setInterval(() => {
        timer -= 1;
        
        if (timer <= 0) {
          clearInterval(countdown);
        } else {
          document.getElementById('info').innerText = `Keep your device disconnected (${timer}s remaining).`;
          document.getElementById('counter').innerText = `Challenge Counter: ${count}`;
        }
      }, 1000);

      setTimeout(endChallenge, timer*1000);
    } else {
      document.getElementById('start-challenge').style.visibility = 'visible';
      console.error("Timer failed to start")
    }
  });
}

function endChallenge() {
  const holder = document.getElementById('data-holder');
  const deviceID = holder.dataset.deviceid;
  console.log(deviceID)
  fetch(`/check-status/${deviceID}/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrftoken
    },
    body: JSON.stringify({ action: 'end' })
  }).then(response => response.json())
  .then(data => {
    let timer = data.interval;
    let count = data.count;
    if (data.status === "ok") {
      console.log("Passed disconnect");
      let checking = false;
      let resolved = false;
      const countdown = setInterval(() => {
        if (resolved) return;
        timer -= 1;
        document.getElementById('counter').innerText = `Challenge Counter: ${count}`

        if (timer <= 0) {
          resolved = true;
          clearInterval(countdown);
          document.getElementById('info').innerText = 'Device failed current test. Disconnect your device now.';
          fetch(`/check-status/${deviceID}/`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRFToken': csrftoken
            },
            body: JSON.stringify({ action: 'fail' })
          }).then(response => response.json())
          .then(data => {
            count = data.count;
            document.getElementById('counter').innerText = `Challenge Counter: ${count}`;
            document.getElementById('start-challenge').style.visibility = 'visible';
          });

        } else if (!checking) {
          document.getElementById('info').innerText = `Reconnect your device within ${timer} seconds`;
          checking = true;
          fetch(`/check-status/${deviceID}/`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRFToken': csrftoken
            },
            body: JSON.stringify({ action: 'check' })
          }).then(response => response.json())
          .then(data => {
            checking = false;
            if (resolved) return;
            count = data.count;
            document.getElementById('counter').innerText = `Challenge Counter: ${count}`
            if (data.status === "ok") {
              resolved = true;
              clearInterval(countdown);
              console.log("Passed reconnect");
              document.getElementById('info').innerText = 'Device passed current test. Disconnect your device now.';
              document.getElementById('start-challenge').style.visibility = 'visible';
            } else if (data.status === "complete") {
              resolved = true;
              clearInterval(countdown);
              console.log("Passed reconnect");
              document.getElementById('info').innerText = 'Ownership challenge completed!';
              window.location.href = data.redirect
            } else {
              console.error("Failed reconnect")
            }
          });
        }
      }, 1000);
    } else {
      console.error("Failed disconnect");
      document.getElementById('info').innerText = 'Device failed current test. Disconnect your device now.';
      document.getElementById('counter').innerText = `Challenge Counter: ${count}`;
      document.getElementById('start-challenge').style.visibility = 'visible';
    }
  });
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

const csrftoken = getCookie('csrftoken');