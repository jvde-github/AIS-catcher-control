// script.js

const jsonTextarea = document.getElementById('json_content');
const saveButton = document.getElementById('save-button');

function escapeHtml(unsafe) {
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

let jsonData; // Global variable to store JSON data
let unsavedChanges = false; // Track unsaved changes
let openPropertiesChannels = new Set(); // Track which channels have properties visible
let isInitializing = false; // Flag to prevent event handlers during initialization
let restartRequired = false; // Tracks if a restart is required
let isSaving = false; // Flag to indicate if a save operation is in progress

function populateChannels(channelType) {
  const container = document.getElementById(`${channelType}-channels-list`);

  if (!container) {
    return;
  }

  isInitializing = true;

  console.log(jsonData);

  container.innerHTML = '';

  if (Array.isArray(jsonData[channelType])) {
    jsonData[channelType].forEach((channel, channelIndex) => {
      const channelDiv = document.createElement('div');
      channelDiv.className = `${channelType}-channel border p-4 rounded-md mb-4`;
      channelDiv.setAttribute('data-index', channelIndex);

      // Determine if the channel is active
      let isActive = true;
      if (channel.hasOwnProperty('active')) {
        const activeValue = channel.active;
        if (typeof activeValue === 'boolean') {
          isActive = activeValue;
        } else if (typeof activeValue === 'string') {
          const activeStr = activeValue.toLowerCase();
          isActive = (activeStr === 'true' || activeStr === 'on');
        } else {
          isActive = false;
        }
      }

      // Build the fixed fields row based on channel type
      let fixedFieldsHtml = '';
      if (channelType === 'udp') {
        fixedFieldsHtml = `
        <!-- Fixed Fields Row for UDP -->
        <div class="flex flex-wrap md:flex-nowrap items-end space-y-2 md:space-y-0 md:space-x-4 mt-4">
          <!-- Broadcast Checkbox -->
          <div class="flex flex-col w-1/2 md:w-1/4">
            <label class="block text-gray-500 text-sm mb-1">Broadcast</label>
            <div class="flex items-center h-[38px] px-4 py-2 border border-gray-300 rounded-md bg-white">
              <input type="checkbox" class="${channelType}-broadcast-checkbox" ${channel.broadcast === true || channel.broadcast === 'true' || channel.broadcast === 'on' ? 'checked' : ''}>
              <span class="ml-2 text-sm text-gray-600">${channel.broadcast === true || channel.broadcast === 'true' || channel.broadcast === 'on' ? 'On' : 'Off'}</span>
            </div>
          </div>
          
          <!-- Message Format Select -->
          <div class="flex flex-col w-1/2 md:w-1/4">
            <label class="block text-gray-500 text-sm mb-1">Message Format</label>
            <select class="${channelType}-msgformat-select block w-full px-4 py-2 border border-gray-300 rounded-md bg-white">
              <option value="NMEA" ${(channel.msgformat || 'NMEA') === 'NMEA' ? 'selected' : ''}>NMEA</option>
              <option value="JSON_NMEA" ${channel.msgformat === 'JSON_NMEA' ? 'selected' : ''}>JSON with NMEA</option>
              <option value="JSON_FULL" ${channel.msgformat === 'JSON_FULL' ? 'selected' : ''}>JSON Full</option>
            </select>
          </div>
        </div>`;
      } else if (channelType === 'tcp') {
        // Default persist to true if not defined
        const isPersist = channel.persist !== false && channel.persist !== 'false' && channel.persist !== 'off';
        fixedFieldsHtml = `
        <!-- Fixed Fields Row for TCP -->
        <div class="flex flex-wrap md:flex-nowrap items-end space-y-2 md:space-y-0 md:space-x-4 mt-4">
          <!-- Auto Reconnect Checkbox -->
          <div class="flex flex-col w-1/2 md:w-1/4">
            <label class="block text-gray-500 text-sm mb-1">Auto Reconnect</label>
            <div class="flex items-center h-[38px] px-4 py-2 border border-gray-300 rounded-md bg-white">
              <input type="checkbox" class="${channelType}-persist-checkbox" ${isPersist ? 'checked' : ''}>
              <span class="ml-2 text-sm text-gray-600">${isPersist ? 'On' : 'Off'}</span>
            </div>
          </div>
          
          <!-- Message Format Select -->
          <div class="flex flex-col w-1/2 md:w-1/4">
            <label class="block text-gray-500 text-sm mb-1">Message Format</label>
            <select class="${channelType}-msgformat-select block w-full px-4 py-2 border border-gray-300 rounded-md bg-white">
              <option value="NMEA" ${(channel.msgformat || 'NMEA') === 'NMEA' ? 'selected' : ''}>NMEA</option>
              <option value="JSON_NMEA" ${channel.msgformat === 'JSON_NMEA' ? 'selected' : ''}>JSON with NMEA</option>
              <option value="JSON_FULL" ${channel.msgformat === 'JSON_FULL' ? 'selected' : ''}>JSON Full</option>
            </select>
          </div>
          
          <!-- Keep Alive Checkbox -->
          <div class="flex flex-col w-1/2 md:w-1/4">
            <label class="block text-gray-500 text-sm mb-1">Keep Alive</label>
            <div class="flex items-center h-[38px] px-4 py-2 border border-gray-300 rounded-md bg-white">
              <input type="checkbox" class="${channelType}-keepalive-checkbox" ${channel.keep_alive === true || channel.keep_alive === 'true' || channel.keep_alive === 'on' ? 'checked' : ''}>
              <span class="ml-2 text-sm text-gray-600">${channel.keep_alive === true || channel.keep_alive === 'true' || channel.keep_alive === 'on' ? 'On' : 'Off'}</span>
            </div>
          </div>
        </div>`;
      } else if (channelType === 'tcp_listener') {
        fixedFieldsHtml = `
        <!-- Fixed Fields Row for TCP Listener -->
        <div class="flex flex-wrap md:flex-nowrap items-end space-y-2 md:space-y-0 md:space-x-4 mt-4">
          <!-- Message Format Select -->
          <div class="flex flex-col w-1/2 md:w-1/4">
            <label class="block text-gray-500 text-sm mb-1">Message Format</label>
            <select class="${channelType}-msgformat-select block w-full px-4 py-2 border border-gray-300 rounded-md bg-white">
              <option value="NMEA" ${(channel.msgformat || 'NMEA') === 'NMEA' ? 'selected' : ''}>NMEA</option>
              <option value="JSON_NMEA" ${channel.msgformat === 'JSON_NMEA' ? 'selected' : ''}>JSON with NMEA</option>
              <option value="JSON_FULL" ${channel.msgformat === 'JSON_FULL' ? 'selected' : ''}>JSON Full</option>
            </select>
          </div>
        </div>`;
      }

      channelDiv.innerHTML = `
      <div class="flex flex-col space-y-4">
        <!-- Mobile Controls Top -->
        <div class="flex items-center justify-between md:hidden">
          <div class="flex items-center space-x-4">
            <!-- Active Checkbox -->
            <div class="flex items-center h-[38px]">
              <input type="checkbox" class="${channelType}-active-checkbox" ${isActive ? 'checked' : ''}>
              <span class="ml-2 text-sm text-gray-600">Active</span>
            </div>
          </div>
          <!-- Delete Channel Button -->
          <button type="button" class="${channelType}-delete-channel-btn text-red-600 hover:text-red-800">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 -960 960 960" fill="currentColor">
              <path d="m256-200-56-56 224-224-224-224 56-56 224 224 224-224 56 56-224 224 224 224-56 56-224-224-224 224Z"/>
            </svg>
          </button>
        </div>
    
        <!-- Main Content Area -->
        <div class="flex flex-wrap md:flex-nowrap items-end space-y-2 md:space-y-0 md:space-x-4">
          <!-- Desktop Controls - Hidden on Mobile -->
          <div class="hidden md:flex items-center h-[38px] w-auto">
            <input type="checkbox" class="${channelType}-active-checkbox mr-2" ${isActive ? 'checked' : ''}>
          </div>
          
          ${channelType === 'tcp_listener' ? '' : `
          <!-- Host Input -->
          <div class="flex flex-col w-full md:w-1/4">
            <label class="block text-gray-500 text-sm mb-1">Host</label>
            <input type="text" value="${escapeHtml(channel.host || '')}" 
              class="${channelType}-host-input block w-full px-4 py-2 border border-gray-300 rounded-md" 
              placeholder="e.g., 192.168.1.101">
          </div>
          `}
          
          <!-- Port Input -->
          <div class="flex flex-col ${channelType === 'tcp_listener' ? 'w-full md:w-1/4' : 'w-1/2 md:w-1/6'}">
            <label class="block text-gray-500 text-sm mb-1">Port</label>
            <input type="number" value="${escapeHtml(channel.port || '')}" 
              class="${channelType}-port-input block w-full px-4 py-2 border border-gray-300 rounded-md" 
              placeholder="10110">
          </div>
          
          <!-- Description Input -->
          <div class="flex flex-col w-full md:flex-1">
            <label class="block text-gray-500 text-sm mb-1 md:hidden lg:block">Description</label>
            <label class="hidden md:block lg:hidden text-gray-500 text-sm mb-1">Desc</label>
            <input type="text" value="${escapeHtml(channel.description || '')}" 
              class="${channelType}-description-input block w-full px-4 py-2 border border-gray-300 rounded-md" 
              placeholder="Optional description">
          </div>
          
          <!-- Desktop Delete Button - Hidden on Mobile -->
          <div class="hidden md:flex items-center h-[38px]">
            <button type="button" class="${channelType}-delete-channel-btn text-red-600 hover:text-red-800">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 -960 960 960" fill="currentColor">
                <path d="m256-200-56-56 224-224-224-224 56-56 224 224 224-224 56 56-224 224 224 224-56 56-224-224-224 224Z"/>
              </svg>
            </button>
          </div>
        </div>
        
        ${fixedFieldsHtml}
      </div>
      `;

      // Attach event listeners after the channel is added to the DOM
      setTimeout(() => {
        // Get both mobile and desktop delete buttons
        const deleteButtons = channelDiv.querySelectorAll(`.${channelType}-delete-channel-btn`);
        deleteButtons.forEach(deleteBtn => {
          deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            deleteChannel(channelType, channelIndex);
          });
        });

        // Input event listeners
        const hostInput = channelDiv.querySelector(`.${channelType}-host-input`);
        const portInput = channelDiv.querySelector(`.${channelType}-port-input`);
        const descriptionInput = channelDiv.querySelector(`.${channelType}-description-input`);
        const activeCheckbox = channelDiv.querySelector(`.${channelType}-active-checkbox`);

        if (hostInput) {
          hostInput.addEventListener('change', (e) => {
            if (!isInitializing) {
              jsonData[channelType][channelIndex].host = e.target.value;
              handleUnsavedChanges(true, 'Host has been modified. Please save your changes.');
              updateJsonTextarea();
            }
          });
        }

        if (portInput) {
          portInput.addEventListener('change', (e) => {
            if (!isInitializing) {
              jsonData[channelType][channelIndex].port = e.target.value;
              handleUnsavedChanges(true, 'Port has been modified. Please save your changes.');
              updateJsonTextarea();
            }
          });
        }

        if (descriptionInput) {
          descriptionInput.addEventListener('change', (e) => {
            if (!isInitializing) {
              jsonData[channelType][channelIndex].description = e.target.value;
              handleUnsavedChanges(true, 'Description has been modified. Please save your changes.');
              updateJsonTextarea();
            }
          });
        }

        if (activeCheckbox) {
          activeCheckbox.addEventListener('change', (e) => {
            if (!isInitializing) {
              jsonData[channelType][channelIndex].active = e.target.checked;
              handleUnsavedChanges(true, 'Active status has been modified. Please save your changes.');
              updateJsonTextarea();
            }
          });
        }

        const broadcastCheckbox = channelDiv.querySelector(`.${channelType}-broadcast-checkbox`);
        if (broadcastCheckbox) {
          broadcastCheckbox.addEventListener('change', (e) => {
            if (!isInitializing) {
              jsonData[channelType][channelIndex].broadcast = e.target.checked;
              // Update the label text
              const label = e.target.nextElementSibling;
              if (label) {
                label.textContent = e.target.checked ? 'On' : 'Off';
              }
              handleUnsavedChanges(true, 'Broadcast setting has been modified. Please save your changes.');
              updateJsonTextarea();
            }
          });
        }

        const persistCheckbox = channelDiv.querySelector(`.${channelType}-persist-checkbox`);
        if (persistCheckbox) {
          persistCheckbox.addEventListener('change', (e) => {
            if (!isInitializing) {
              jsonData[channelType][channelIndex].persist = e.target.checked;
              // Update the label text
              const label = e.target.nextElementSibling;
              if (label) {
                label.textContent = e.target.checked ? 'On' : 'Off';
              }
              handleUnsavedChanges(true, 'Auto Reconnect setting has been modified. Please save your changes.');
              updateJsonTextarea();
            }
          });
        }

        const keepAliveCheckbox = channelDiv.querySelector(`.${channelType}-keepalive-checkbox`);
        if (keepAliveCheckbox) {
          keepAliveCheckbox.addEventListener('change', (e) => {
            if (!isInitializing) {
              jsonData[channelType][channelIndex].keep_alive = e.target.checked;
              // Update the label text
              const label = e.target.nextElementSibling;
              if (label) {
                label.textContent = e.target.checked ? 'On' : 'Off';
              }
              handleUnsavedChanges(true, 'Keep Alive setting has been modified. Please save your changes.');
              updateJsonTextarea();
            }
          });
        }

        const msgformatSelect = channelDiv.querySelector(`.${channelType}-msgformat-select`);
        if (msgformatSelect) {
          msgformatSelect.addEventListener('change', (e) => {
            if (!isInitializing) {
              jsonData[channelType][channelIndex].msgformat = e.target.value;
              handleUnsavedChanges(true, 'Message format has been modified. Please save your changes.');
              updateJsonTextarea();
            }
          });
        }
      }, 0);

      container.appendChild(channelDiv);
    });
  }

  isInitializing = false;
}

// Generic function to create property badges for channels
function createChannelPropertyBadge(channelType, channelIndex, key, value) {
  const badge = document.createElement('div');
  badge.className = 'flex items-center bg-white text-black px-2 py-0.5 border border-gray-300 rounded-full mr-2 mb-2';

  badge.setAttribute('data-key', key);

  badge.innerHTML = `
    <span class="mr-4 text-sm"><strong>${escapeHtml(key)}</strong>: ${escapeHtml(value)}</span>
    <button type="button" class="${channelType}-edit-property-btn text-gray-600 hover:text-gray-800" title="Edit Property">
      <!-- Edit icon SVG -->
      <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 -960 960 960" fill="currentColor">
        <path d="M200-200h57l391-391-57-57-391 391v57Zm-80-80v-170l528-527q12-11 26.5-17t30.5-6q16 0 31 6t26 18l55 56q12 11 17.5 26t5.5 30q0 16-5.5 30.5T817-647L290-120H120Zm640-584-56-56 56 56Zm-141 85-28-29 57 57-29-28Z"/>
      </svg>
    </button>
    <button type="button" class="${channelType}-remove-property-btn text-red-600 hover:text-red-800 ml-1" title="Remove Property">
      <!-- Remove icon SVG -->
      <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 -960 960 960" fill="currentColor">
        <path d="m256-200-56-56 224-224-224-224 56-56 224 224 224-224 56 56-224 224 224 224-56 56-224-224-224 224Z"/>
      </svg>
    </button>
  `;

  badge.querySelector(`.${channelType}-remove-property-btn`).addEventListener('click', () => {
    removeChannelProperty(channelType, channelIndex, key);
    openPropertiesChannels.add(`${channelType}-${channelIndex}`);
    updateSaveButton();
  });

  badge.querySelector(`.${channelType}-edit-property-btn`).addEventListener('click', () => {
    editChannelProperty(channelType, channelIndex, key);
    openPropertiesChannels.add(`${channelType}-${channelIndex}`);
    updateSaveButton();
  });

  return badge;
}

// Generic function to delete a channel
function deleteChannel(channelType, channelIndex) {
  // Remove from jsonData
  jsonData[channelType].splice(channelIndex, 1);

  // Remove from openPropertiesChannels if present
  openPropertiesChannels.delete(`${channelType}-${channelIndex}`);

  // Mark as unsaved and update UI
  handleUnsavedChanges(true, `${capitalizeFirstLetter(channelType)} channel has been deleted. Please save your changes.`);
  updateJsonTextarea();

  // Re-populate the channels
  populateChannels(channelType);
}

// Generic function to add a property to a channel
function addChannelProperty(channelType, channelIndex) {
  const key = prompt("Enter property name:");
  if (!key) return;
  const value = prompt(`Enter value for ${key}:`);
  if (value === null) return;

  // Update jsonData
  jsonData[channelType][channelIndex][key] = value;

  // Add to openPropertiesChannels to keep properties visible
  openPropertiesChannels.add(`${channelType}-${channelIndex}`);

  // Mark as unsaved and update UI
  handleUnsavedChanges(true, `Property "${key}" has been added. Please save your changes.`);
  updateJsonTextarea();

  // Re-populate the channels
  populateChannels(channelType);
}

// Generic function to remove a property from a channel
function removeChannelProperty(channelType, channelIndex, key) {
  // Remove from jsonData
  delete jsonData[channelType][channelIndex][key];

  // Add to openPropertiesChannels to keep properties visible
  openPropertiesChannels.add(`${channelType}-${channelIndex}`);

  // Mark as unsaved and update UI
  handleUnsavedChanges(true, `Property "${key}" has been removed. Please save your changes.`);
  updateJsonTextarea();

  // Re-populate the channels
  populateChannels(channelType);
}

// Generic function to edit a property of a channel
function editChannelProperty(channelType, channelIndex, key) {
  const value = prompt(`Enter new value for ${key}:`, jsonData[channelType][channelIndex][key]);
  if (value === null) return;

  // Update jsonData
  jsonData[channelType][channelIndex][key] = value;

  // Add to openPropertiesChannels to keep properties visible
  openPropertiesChannels.add(`${channelType}-${channelIndex}`);

  // Mark as unsaved and update UI
  handleUnsavedChanges(true, `Property "${key}" has been updated. Please save your changes.`);
  updateJsonTextarea();

  // Re-populate the channels
  populateChannels(channelType);
}

// Generic function to add a new channel
function addChannel(channelType) {
  // Initialize the channel array if it doesn't exist
  if (!Array.isArray(jsonData[channelType])) {
    jsonData[channelType] = [];
  }

  // Add a new channel with default values based on type
  const defaultChannel = {
    port: "",
    active: true,
    description: ""
  };

  if (channelType === 'udp') {
    defaultChannel.host = "";
    defaultChannel.broadcast = false;
    defaultChannel.msgformat = "NMEA";
  } else if (channelType === 'tcp') {
    defaultChannel.host = "";
    defaultChannel.persist = true;
    defaultChannel.msgformat = "NMEA";
    defaultChannel.keep_alive = false;
  } else if (channelType === 'tcp_listener') {
    defaultChannel.msgformat = "NMEA";
  }

  jsonData[channelType].push(defaultChannel);

  // Add to openPropertiesChannels to keep properties visible for the new channel
  const newChannelIndex = jsonData[channelType].length - 1;
  openPropertiesChannels.add(`${channelType}-${newChannelIndex}`);

  // Mark as unsaved and update UI
  handleUnsavedChanges(true, `${capitalizeFirstLetter(channelType)} channel has been added. Please save your changes.`);
  updateJsonTextarea();

  // Re-populate the channels to reflect the new addition
  populateChannels(channelType);
}

// Function to update the JSON textarea
function updateJsonTextarea() {
  const jsonTextarea = document.getElementById('json_content');
  jsonTextarea.innerText = JSON.stringify(jsonData, null, 2);
}

function handleUnsavedChanges(isUnsaved, message = 'You have unsaved changes.') {
  unsavedChanges = isUnsaved;
  updateSaveButton();

  if (unsavedChanges) {
    updateStatusMessage('warning', message);
    window.addEventListener('beforeunload', beforeUnloadHandler);
  } else {
    // Only show success message if restart is required
    if (restartRequired) {
      updateStatusMessage('control', 'Changes saved. They will take effect after restarting AIS-catcher.');
    } else {
      updateStatusMessage(); // Hide any status message
    }
    window.removeEventListener('beforeunload', beforeUnloadHandler);
  }
}

// Function to handle the beforeunload event
function beforeUnloadHandler(e) {
  if (unsavedChanges && !isSaving) {
    e.preventDefault();
    e.returnValue = '';
  }
}

// Function to update the save button's appearance
function updateSaveButton() {
  const saveButton = document.getElementById('save-button');
  if (unsavedChanges) {
    saveButton.classList.remove('bg-gray-500');
    saveButton.classList.add('bg-green-500');
  } else {
    saveButton.classList.remove('bg-green-500');
    saveButton.classList.add('bg-gray-500');
  }
}

// Function to toggle the visibility of JSON content
function toggleJsonContent() {
  const contentContainer = document.getElementById('json-content-container');
  const chevronIcon = document.getElementById('chevron-icon');
  const toggleText = chevronIcon.nextElementSibling;

  contentContainer.classList.toggle('hidden');

  if (contentContainer.classList.contains('hidden')) {
    // Collapsed state
    chevronIcon.classList.remove('rotate-180');
    toggleText.textContent = 'Show JSON Content';
  } else {
    // Expanded state
    chevronIcon.classList.add('rotate-180');
    toggleText.textContent = 'Hide JSON Content';
  }
}

// Function to save data to the server
function saveData() {
  isSaving = true; // Indicate that a save operation is in progress

  fetch('/udp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(jsonData)
  })
    .then(response => {
      isSaving = false; // Save operation completed
      if (response.ok) {
        handleUnsavedChanges(false);
        restartRequired = true;
      } else {
        response.text().then(text => {
          updateStatusMessage('error', `Error saving data: ${text}`);
        });
      }
    })
    .catch((error) => {
      isSaving = false; // Save operation completed
      console.error('Error:', error);
      updateStatusMessage('error', `Error saving data: ${error.message}`);
    });
}

function updateStatusMessage(type, message) {
  const statusMessageDiv = document.getElementById('status-message');

  if (!type || !message) {
    // Hide the status message
    statusMessageDiv.innerHTML = '';
    statusMessageDiv.className = 'hidden';
    return;
  }

  let bgClass, borderClass, textClass;

  switch (type) {
    case 'good':
      bgClass = 'bg-green-100';
      borderClass = 'border-green-400';
      textClass = 'text-green-700';
      break;
    case 'control':
      bgClass = 'bg-green-100';
      borderClass = 'border-green-400';
      textClass = 'text-green-700';
      break;
    case 'warning':
      bgClass = 'bg-yellow-100';
      borderClass = 'border-yellow-400';
      textClass = 'text-yellow-700';
      break;
    case 'error':
      bgClass = 'bg-red-100';
      borderClass = 'border-red-400';
      textClass = 'text-red-700';
      break;
    default:
      // Default to info or neutral styling
      bgClass = 'bg-blue-100';
      borderClass = 'border-blue-400';
      textClass = 'text-blue-700';
  }

  if (type === 'control') {
    statusMessageDiv.innerHTML = `
      <div class="flex items-center justify-between gap-4">
        <span>${escapeHtml(message)}</span>
        <a href="/control" class="inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
          Control
        </a>
      </div>
    `;
  }
  else {
    statusMessageDiv.innerHTML = `
    <div class="flex items-center">
      <span>${escapeHtml(message)}</span>
    </div>
  `;
  }

  statusMessageDiv.className = `mt-2 p-2 ${bgClass} ${borderClass} ${textClass} rounded`;
}

// Helper function to capitalize the first letter of a string
function capitalizeFirstLetter(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

function toggleSharingKeyInput(isEnabled) {
  const sharingKeyContainer = document.getElementById('sharing-key-container');
  if (isEnabled) {
    sharingKeyContainer.classList.remove('hidden');
  } else {
    sharingKeyContainer.classList.add('hidden');
    // Removed the following lines to prevent clearing the UUID
    // const sharingKeyInput = document.getElementById('sharing-key');
    // sharingKeyInput.value = '';
    // if (jsonData.sharing) {
    //   delete jsonData.sharing_key;
    // }
  }
}

/**
 * Sets up the Sharing Key input field to update jsonData on change.
 */
function setupSharingKeyInput() {
  const sharingKeyInput = document.getElementById('sharing-key');

  // Initialize the input based on jsonData
  if (jsonData && jsonData.sharing && jsonData.sharing_key) {
    sharingKeyInput.value = jsonData.sharing_key;
  }

  // Initial state of the Register button
  updateRegisterButtonState();

  // Event listener for the sharing key input
  sharingKeyInput.addEventListener('input', (e) => {
    const key = e.target.value.trim();
    if (key) {
      // Simple UUID validation (basic)
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      if (uuidRegex.test(key)) {
        jsonData.sharing_key = key;
        handleUnsavedChanges(true, 'Sharing UUID has been modified. Please save your changes.');
        updateStatusMessage('warning', 'Valid Sharing Key entered. Save and Restart AIS-catcher to apply changes.');
      } else {
        updateStatusMessage('error', 'Invalid UUID format for Sharing Key.');
      }
    } else {
      // If the input is cleared
      delete jsonData.sharing_key;
      handleUnsavedChanges(true, 'Sharing Key has been cleared. Please save your changes.');
      updateStatusMessage('warning', 'Sharing Key is optional.');
    }
    updateJsonTextarea();

    // Update the Register button state
    updateRegisterButtonState();
  });

  // Optional: Handle the "Create Sharing Key" button
  const createSharingKeyBtn = document.getElementById('create-sharing-key-btn');
  createSharingKeyBtn.addEventListener('click', () => {
    window.open('https://aiscatcher.org/register', '_blank');
  });
}

/**
 * Updates the state of the Register button based on the presence of a valid Sharing Key UUID.
 */
function updateRegisterButtonState() {
  const registerButton = document.getElementById('register-button');
  const sharingKeyInput = document.getElementById('sharing-key');

  if (!registerButton || !sharingKeyInput) {
    console.warn('Register button or Sharing Key input not found.');
    return; // Exit if elements are not found
  }

  const key = sharingKeyInput.value.trim();
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  if (uuidRegex.test(key)) {
    // Disable the Register button
    registerButton.disabled = true;
    registerButton.classList.add('opacity-50', 'cursor-not-allowed');
    registerButton.classList.remove('bg-blue-500', 'hover:bg-blue-700');

    // Optionally, add a tooltip to inform the user why it's disabled
    registerButton.title = 'Register is disabled because a valid Sharing Key is already entered.';
  } else {
    // Enable the Register button
    registerButton.disabled = false;
    registerButton.classList.remove('opacity-50', 'cursor-not-allowed');
    registerButton.classList.add('bg-blue-500', 'hover:bg-blue-700');

    // Remove the tooltip
    registerButton.title = '';
  }
}


/**
 * Initializes the Sharing Channel section.
 */
function initializeSharingChannel() {
  const container = document.getElementById(`sharing-channel`);

  if (!container) {
    return;
  }

  isInitializing = true; // Start initialization

  setupSharingToggle();
  setupSharingKeyInput();

  // Update the Register button state after initialization
  updateRegisterButtonState();

  isInitializing = false; // End initialization
}

function updateFormFromJson(json, map) {
  for (const [elementId, jsonPath] of Object.entries(map)) {
    const element = document.getElementById(elementId);
    if (!element) continue;

    const value = getValueFromJsonPath(json, jsonPath);
    if (value !== undefined) {
      if (element.type === "checkbox") {
        element.checked = Boolean(value);
        element.dispatchEvent(new Event('change'));
      } else if (element.type === "button" && element.getAttribute("role") === "switch") {
        element.setAttribute("aria-checked", value ? "true" : "false");
        toggleSwitchStyle(element, value);
      } else {
        element.value = value;
      }
    }
  }
}

function updateJsonFromForm(json, map, elementId = null) {
  if (elementId) {
    const jsonPath = map[elementId];
    const element = document.getElementById(elementId);
    if (element) {
      let value;
      if (element.type === "checkbox") {
        value = element.checked;
      } else if (element.type === "button" && element.getAttribute("role") === "switch") {
        value = element.getAttribute("aria-checked") === "true";
      } else {
        value = element.value;
      }
      setValueInJsonPath(json, jsonPath, value);
    }
  } else {
    for (const [elementId, jsonPath] of Object.entries(map)) {
      const element = document.getElementById(elementId);
      if (!element) continue;

      let value;
      if (element.type === "checkbox") {
        value = element.checked;
      } else if (element.type === "button" && element.getAttribute("role") === "switch") {
        value = element.getAttribute("aria-checked") === "true";
      } else {
        value = element.value;
      }

      setValueInJsonPath(json, jsonPath, value);
    }
  }
}

function getValueFromJsonPath(obj, path) {
  return path.split('.').reduce((acc, part) => acc && acc[part], obj);
}

function setValueInJsonPath(obj, path, value) {
  const parts = path.split('.');
  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (!current[part]) {
      current[part] = {}; // Create nested structure if it doesn't exist
    }
    current = current[part];
  }
  current[parts[parts.length - 1]] = value;
}

function toggleSwitchStyle(element, isChecked) {
  const knob = element.querySelector('span');
  element.classList.toggle('bg-yellow-500', isChecked);
  knob.style.transform = isChecked ? 'translateX(1.5rem)' : 'translateX(0.25rem)';
}

function addFormEventListeners(json, map) {
  for (const [elementId, jsonPath] of Object.entries(map)) {
    const element = document.getElementById(elementId);
    if (!element) continue;

    // Determine the appropriate event type
    const eventType = (element.type === "button" && element.getAttribute("role") === "switch") ? "click" : "input";

    element.addEventListener(eventType, () => {
      // Update only the specific field that changed
      updateJsonFromForm(json, map, elementId);
      handleUnsavedChanges(true, 'You have unsaved changes. Please save your changes.');
      updateJsonTextarea(); // Update JSON textarea display
    });

    // If the element is a switch, handle the toggle separately for visual updates
    if (element.getAttribute("role") === "switch") {
      element.addEventListener('click', () => {
        const isChecked = element.getAttribute('aria-checked') === 'true';
        const newState = !isChecked;
        element.setAttribute('aria-checked', newState);
        toggleSwitchStyle(element, newState);
        updateJsonFromForm(json, map, elementId);
        updateJsonTextarea();
      });
    }

    if (element.tagName.toLowerCase() === 'select' || element.getAttribute("role") === "switch") {
      const event = new Event('change', { bubbles: true });
      element.dispatchEvent(event);
    }
  }
}


// Automatically populate channels on page load
document.addEventListener('DOMContentLoaded', () => {

  if (jsonTextarea) {
    try {
      jsonData = JSON.parse(jsonTextarea.innerText);
    } catch (e) {
      alert("Invalid JSON format. Please check the JSON content.");
      console.error("JSON Parse Error:", e);
      return;
    }

    populateChannels('udp');
    populateChannels('tcp');
    populateChannels('tcp_listener');
    initializeSharingChannel();
    updateJsonTextarea();


    if (typeof formToJsonMap !== 'undefined' && typeof jsonData !== 'undefined') {
      updateFormFromJson(jsonData, formToJsonMap);
      addFormEventListeners(jsonData, formToJsonMap);

    }
  }
});

// Check if the save button exists
if (saveButton) {
  // Add event listener to the save button
  saveButton.addEventListener('click', function (e) {
    e.preventDefault();
    saveData();
  });
} else {
  console.warn("Save button with ID 'save-button' was not found in the DOM.");
}
