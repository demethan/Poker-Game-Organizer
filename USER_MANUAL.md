# User Manual — Luck's Poker Game Organizer

## Organizer Guide

### 1) Create an Organizer Account
- Open `/register`
- Enter name, email, and password
- Log in at `/login`

### 2) Create a Game
- Go to `/games/new`
- Fill in title, location, date, time, and total players
- Your name is added as **HOST** automatically
- The form auto-fills from your last game

### 3) Share the Invite Link
- On the dashboard or game view, click **Copy Invite Link**
- Send the link via text to invitees

### 4) Monitor the Game
- Open the game view from your dashboard
- See RSVP list, status, ETA, and standby list
- Standby list shows position in order

### 5) Delete a Game
- Open the game view
- Click **Delete Game**

---

## Invitee Guide

### 1) Open the Invite Link
- The link opens the game invite page

### 2) RSVP
- Enter your name
- Tap **IN**, **LATE**, or **OUT**
- If **LATE**, add an ETA

### 3) Full Games
- If the game is full, you’ll see the standby page
- Tap **Add me to standby list**
- You’ll receive your standby position
- If you return later, it shows you’re already on standby

### 4) Location Link
- The address opens in Google Maps

---

## Admin Guide

### 1) Login
- Admins log in using **username** and password
- Go to `/admin`

### 2) Manage Users
- **Disable**: blocks login
- **Enable**: restores login
- **Reset Password**: shows a temporary password
- **Delete**: removes the user and their games/RSVPs

---

## Tips
- Use a strong `SESSION_SECRET` in production
- Standby order is first-come, first-served
- LATE counts as IN for capacity

## Troubleshooting
- If you see a 502 error, check `poker-app` service status
- If the page looks cached after changes, hard refresh

