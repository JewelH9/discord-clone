# 🧪 Discord Clone - Complete Testing Guide

## **Prerequisites**
1. MongoDB running and connected
2. Backend running on port 5000
3. Frontend running on port 3000
4. At least 2 browser windows for testing real-time features

---

## **Test Checklist**

### **✅ 1. Authentication**
- [ ] Register new account
- [ ] Login with credentials
- [ ] Logout and login again
- [ ] Token persists on refresh

### **✅ 2. Server Management**
- [ ] Create a new server
- [ ] Server appears in left sidebar
- [ ] Click server to view channels
- [ ] Generate invite code
- [ ] Join server with invite code (use second browser)
- [ ] View server settings (click server name dropdown)
- [ ] Update server name/description
- [ ] View members list
- [ ] Change member roles (if admin)
- [ ] Kick member (if admin)
- [ ] Leave server (non-owner)
- [ ] Delete server (owner only)

### **✅ 3. Channel Categories**
- [ ] View default categories (Text Channels, Voice Channels)
- [ ] Click different text channels
- [ ] Messages load for each channel
- [ ] Channel names display correctly

### **✅ 4. Messaging**
- [ ] Send message in channel
- [ ] Message appears instantly
- [ ] Other user sees message in real-time
- [ ] Edit own message
- [ ] Delete own message
- [ ] See "(edited)" tag on edited messages
- [ ] Typing indicator appears when typing
- [ ] Typing indicator disappears after 3 seconds

### **✅ 5. Reactions**
- [ ] Hover over message to see reaction button
- [ ] Click reaction button
- [ ] Select emoji from picker
- [ ] Reaction appears on message
- [ ] Click reaction again to remove
- [ ] See reaction count
- [ ] Other users see reactions in real-time

### **✅ 6. Threads/Replies**
- [ ] Click thread button on message
- [ ] Thread modal opens
- [ ] Send reply in thread
- [ ] Reply appears in thread
- [ ] Reply count shows on original message
- [ ] Click reply count to open thread

### **✅ 7. Pinned Messages**
- [ ] Click pin icon in channel header
- [ ] Empty state shows if no pins
- [ ] Pin a message (moderator/admin)
- [ ] Message appears in pinned list
- [ ] Unpin message
- [ ] Message removed from pinned list

### **✅ 8. User Profiles**
- [ ] Click user avatar
- [ ] Profile modal opens
- [ ] See username, status, member since
- [ ] See last seen if offline
- [ ] See custom status if set
- [ ] Close profile

### **✅ 9. Direct Messages**
- [ ] Click DM icon (speech bubble) in left sidebar
- [ ] Click "Message" button on member
- [ ] DM conversation opens
- [ ] Send DM
- [ ] Receive DM in real-time
- [ ] DM appears in DM list
- [ ] Switch between DMs

### **✅ 10. Voice Chat**
- [ ] Click voice channel
- [ ] Browser asks for microphone permission
- [ ] Grant permission
- [ ] "Voice Connected" box appears
- [ ] Microphone visualizer shows levels
- [ ] Green bars move when speaking
- [ ] Click mute button
- [ ] Mic icon turns red
- [ ] Click deafen button
- [ ] Can't hear others (if multiple users)
- [ ] Click disconnect
- [ ] Voice box disappears

### **✅ 11. User Blocking**
- [ ] Hover over another user's message
- [ ] Click block button
- [ ] Confirm block
- [ ] Refresh page
- [ ] Blocked user's messages don't appear
- [ ] Unblock from settings (future feature)

### **✅ 12. Search Messages**
- [ ] Click search icon in server dropdown
- [ ] Type search query
- [ ] Results appear
- [ ] Click result to see context
- [ ] Search filters by channel

### **✅ 13. Subscription/Upgrade**
- [ ] Click star icon in bottom left
- [ ] Subscription modal opens
- [ ] See 3 tiers: Free, Pro, Premium
- [ ] Click Pro
- [ ] Click "Upgrade to Pro"
- [ ] Success message appears
- [ ] Badge shows "PRO MEMBER"
- [ ] Create more servers (limit increased)

### **✅ 14. Online/Offline Status**
- [ ] User shows as online when connected
- [ ] Green dot appears
- [ ] Close browser tab
- [ ] User shows as offline in other browser
- [ ] Gray dot appears
- [ ] Last seen timestamp shows

### **✅ 15. Unread Messages**
- [ ] Send message in channel (from second browser)
- [ ] Red badge appears on server icon
- [ ] Badge shows unread count
- [ ] Click server
- [ ] Badge disappears

### **✅ 16. Custom Status**
- [ ] Click status in bottom left
- [ ] Type custom status
- [ ] Press Enter
- [ ] Status saves
- [ ] Status shows in profile
- [ ] Other users see status

### **✅ 17. Animations & Polish**
- [ ] Messages slide up when appearing
- [ ] Modals fade in
- [ ] Hover effects work smoothly
- [ ] Typing dots animate
- [ ] Online status pulses
- [ ] Microphone visualizer animates

### **✅ 18. Sound & Notifications**
- [ ] Receive message (tab in background)
- [ ] Desktop notification appears
- [ ] Sound plays
- [ ] Click notification to focus window

---

## **Common Issues & Solutions**

### **Voice Chat Issues**
- **Problem:** "Could not access microphone"
- **Solution:** 
  1. Check browser URL bar for blocked permissions
  2. Click lock icon → Allow microphone
  3. Refresh page and try again

### **Messages Not Appearing**
- **Problem:** Messages don't show in real-time
- **Solution:**
  1. Check browser console for errors
  2. Verify backend is running
  3. Check socket connection in Network tab

### **Server Limit Reached**
- **Problem:** "You've reached your server limit"
- **Solution:**
  1. Upgrade subscription
  2. Or delete old servers

---

## **Performance Testing**

### **Test with Multiple Users**
1. Open 3+ browser windows
2. Login with different accounts
3. All join same server
4. Send messages rapidly
5. Verify all messages appear
6. Check for lag or delays

### **Test with Many Messages**
1. Send 50+ messages in channel
2. Scroll to top
3. Verify smooth scrolling
4. Check memory usage in DevTools

---

## **Browser Compatibility**
- [ ] Chrome (recommended)
- [ ] Firefox
- [ ] Edge
- [ ] Safari (may have WebRTC issues)

---

## **Final Checklist**
- [ ] All features tested
- [ ] No console errors
- [ ] Real-time updates work
- [ ] UI is responsive
- [ ] Animations are smooth
- [ ] No memory leaks

**🎉 If all tests pass, your Discord clone is production-ready!**