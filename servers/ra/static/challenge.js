function startChallenge() {
  fetch('/start-challenge/', {
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
      let timer = parseInt(data.timer);
      console.log(timer);

      const countdown = setInterval(() => {
        timer -= 1;
        
        if (timer <= 0) {
          clearInterval(countdown);
        } else {
          document.getElementById('info').innerText = `Keep your device disconnected (${timer}s remaining)`;
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
  fetch(`/end-challenge/${deviceID}/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrftoken
    },
    body: JSON.stringify({ action: 'end' })
  }).then(response => response.json())
  .then(data => {
    if (data.status === "before") {
      console.log("Passed");
      let timer=10;
      const countdown = setInterval(() => {
        timer -= 1;
        
        if (timer <= 0) {
          clearInterval(countdown);
          document.getElementById('info').innerText = 'Device failed current test';
        } else {
          document.getElementById('info').innerText = `Reconnect your device within ${timer} seconds`;
        }

        fetch(`/end-challenge/${deviceID}/`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrftoken
          },
          body: JSON.stringify({ action: 'check' })
        }).then(response => response.json())
        .then(data => {
          if (data.status === "between") {
            console.log("Passed");
            document.getElementById('info').innerText = 'Device passed current test';
            clearInterval(countdown);
          } else {
            console.error("Failed")
          }
        });
      }, 1000);
    } else {
      console.error("Failed")
      document.getElementById('info').innerText = 'Device failed current test';
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