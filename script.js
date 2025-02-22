// script.js
async function testLogin() {
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    const response = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await response.json();
    document.getElementById('loginResult').textContent = JSON.stringify(data);
    if (data.token) {
        localStorage.setItem('token', data.token);
    }
}

async function testGenerateLink() {
    const username = document.getElementById('linkUsername').value;
    const response = await fetch('/generate-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });
    const data = await response.json();
    document.getElementById('linkResult').textContent = JSON.stringify(data);
}

async function testGetTime() {
    const token = localStorage.getItem('token');
    const response = await fetch('/time', {
        headers: { 'Authorization': token }
    });
    const data = await response.json();
    document.getElementById('timeResult').textContent = JSON.stringify(data);
}

async function testKickout() {
    const username = document.getElementById('kickoutUsername').value;
    const response = await fetch('/kickout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });
    const data = await response.json();
    document.getElementById('kickoutResult').textContent = JSON.stringify(data);
}

document.getElementById('loginButton').addEventListener('click', testLogin);
document.getElementById('generateLinkButton').addEventListener('click', testGenerateLink);
document.getElementById('getTimeButton').addEventListener('click', testGetTime);
document.getElementById('kickoutButton').addEventListener('click', testKickout);