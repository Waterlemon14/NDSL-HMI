function startChallenge() {
  const holder = document.getElementById('data-holder');
  const deviceID = holder.dataset.deviceid;
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
          document.getElementById('info').innerText = `Keep your device disconnected (${timer}s remaining)`;
          document.getElementById('counter').innerText = `Challenge Counter: ${count}`;
        }
      }, 1000);

      setTimeout(endChallenge, timer*1000);
      document.getElementById('start-challenge').style.visibility = 'hidden';
    } else {
      console.error("Timer failed to start")
    }
  });
}

function endChallenge() {
  document.getElementById('start-challenge').style.visibility = 'visible';
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
      const countdown = setInterval(() => {
        timer -= 1;
        document.getElementById('counter').innerText = `Challenge Counter: ${count}`

        if (timer <= 0) {
          clearInterval(countdown);
          document.getElementById('info').innerText = 'Device failed current test';
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
          });
        } else {
          document.getElementById('info').innerText = `Reconnect your device within ${timer} seconds`;
        }

        fetch(`/check-status/${deviceID}/`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrftoken
          },
          body: JSON.stringify({ action: 'check' })
        }).then(response => response.json())
        .then(data => {
          count = data.count;
          document.getElementById('counter').innerText = `Challenge Counter: ${count}`
          if (data.status === "ok") {
            console.log("Passed reconnect");
            document.getElementById('info').innerText = 'Device passed current test';
            clearInterval(countdown);
          } else {
            console.error("Failed reconnect")
          }
        });
      }, 1000);
    } else {
      console.error("Failed disconnect");
      document.getElementById('info').innerText = 'Device failed current test';
      document.getElementById('counter').innerText = `Challenge Counter: ${count}`;
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