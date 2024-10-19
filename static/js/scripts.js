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

function toggleSubmenu(submenuId, chevronId) {
  const submenu = document.getElementById(submenuId);
  const chevron = document.getElementById(chevronId);
  const isOpen = submenu.classList.contains('open');

  // Close all submenus
  document.querySelectorAll('.submenu').forEach(sm => {
    sm.classList.remove('open');
    sm.classList.add('hidden');
  });

  // Reset all chevrons
  document.querySelectorAll('svg[id$="-chevron"]').forEach(c => {
    c.classList.remove('transform', 'rotate-180');
  });

  // Toggle the clicked submenu
  if (!isOpen) {
    submenu.classList.add('open');
    submenu.classList.remove('hidden');
    chevron.classList.add('transform', 'rotate-180');
  }
}

// Generic function to populate channels (UDP, TCP, etc.)
function populateChannels(channelType) {
  const container = document.getElementById(`${channelType}-channels-list`);

  if (!container) {
    return;
  }

  isInitializing = true; // Start initialization

  // Parse JSON content
  console.log(jsonData);

  container.innerHTML = '';

  if (Array.isArray(jsonData[channelType])) {
    jsonData[channelType].forEach((channel, index) => {
      const channelIndex = index;
      const propertiesListId = `${channelType}-properties-list-${channelIndex}`;
      const toggleButtonId = `${channelType}-toggle-btn-${channelIndex}`;

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

      // Create Channel Container
      const channelDiv = document.createElement('div');
      channelDiv.className = `${channelType}-channel border p-4 rounded-md mb-4`;
      channelDiv.setAttribute('data-index', channelIndex);

      // Determine if properties should be visible
      const openChannelKey = `${channelType}-${channelIndex}`;
      const shouldShowProperties = openPropertiesChannels.has(openChannelKey);

      // Create the content for the channel
      channelDiv.innerHTML = `
        <div class="flex items-end space-x-4">
          <!-- Active Checkbox -->
          <div class="flex items-center h-[38px]">
            <input type="checkbox" class="${channelType}-active-checkbox mr-2" ${isActive ? 'checked' : ''}>
          </div>
          <!-- Host Input -->
          <div class="flex flex-col w-1/5">
            <label class="block text-gray-500 text-sm mb-1">Host</label>
            <input type="text" value="${escapeHtml(channel.host || '')}" 
              class="${channelType}-host-input block w-full px-4 py-2 border border-gray-300 rounded-md" 
              placeholder="e.g., 192.168.1.101">
          </div>
          <!-- Port Input -->
          <div class="flex flex-col w-1/6">
            <label class="block text-gray-500 text-sm mb-1">Port</label>
            <input type="number" value="${escapeHtml(channel.port || '')}" 
              class="${channelType}-port-input block w-full px-4 py-2 border border-gray-300 rounded-md" 
              placeholder="10110">
          </div>
          <!-- Description Input -->
          <div class="flex flex-col flex-grow">
            <label class="block text-gray-500 text-sm mb-1">Description</label>
            <input type="text" value="${escapeHtml(channel.description || '')}" 
              class="${channelType}-description-input block w-full px-4 py-2 border border-gray-300 rounded-md" 
              placeholder="Optional description">
          </div>
          <!-- Action Buttons -->
          <div class="flex items-center space-x-2 h-[38px]">
            <!-- Toggle Properties Button -->
            <button type="button" class="${channelType}-toggle-properties-btn text-gray-600 hover:text-gray-800" id="${toggleButtonId}">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 transition-transform duration-200 ${shouldShowProperties ? 'transform rotate-180' : ''}" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.71a.75.75 0 111.06 1.06l-4.24 4.24a.75.75 0 01-1.06 0L5.25 8.29a.75.75 0 01-.02-1.06z" clip-rule="evenodd" />
              </svg>
            </button>
            <!-- Delete Channel Button -->
            <button type="button" class="${channelType}-delete-channel-btn text-red-600 hover:text-red-800">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 -960 960 960" fill="currentColor">
                <path d="m256-200-56-56 224-224-224-224 56-56 224 224 224-224 56 56-224 224 224 224-56 56-224-224-224 224Z"/>
              </svg>
            </button>
          </div>
        </div>
        <!-- Properties Badges (Initially Hidden or Visible based on shouldShowProperties) -->
        <div class="flex flex-wrap items-center space-x-2 mt-2 ${shouldShowProperties ? '' : 'hidden'}" id="${propertiesListId}">
          <!-- Property Badges and Add Property Button will appear here -->
        </div>
      `;

      // Get the properties container
      const propertiesContainer = channelDiv.querySelector(`#${propertiesListId}`);

      // Add "Add Property" Button before the badges
      const addPropertyBtn = document.createElement('button');
      addPropertyBtn.type = 'button';
      addPropertyBtn.className = `${channelType}-add-property-btn flex items-center justify-center bg-white text-gray-600 hover:text-gray-800 border border-gray-300 rounded-full mr-2 mb-2 h-6 w-6`;
      addPropertyBtn.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 -960 960 960" width="24px" fill="#5f6368"><path d="M440-440H200v-80h240v-240h80v240h240v80H520v240h-80v-240Z"/></svg>
      `;
      addPropertyBtn.addEventListener('click', () => {
        addChannelProperty(channelType, channelIndex);
      });
      propertiesContainer.appendChild(addPropertyBtn);

      // Append Properties as Badges (excluding specific keys)
      for (const [key, value] of Object.entries(channel)) {
        if (!['host', 'port', 'active', 'description'].includes(key)) {
          const badge = createChannelPropertyBadge(channelType, channelIndex, key, value);
          propertiesContainer.appendChild(badge);
        }
      }

      // Attach event listeners to inputs and buttons
      const hostInput = channelDiv.querySelector(`.${channelType}-host-input`);

      hostInput.addEventListener('change', (e) => {
        console.log('Host input changed:', e.target.value, isInitializing, e.target.value);
        jsonData[channelType][channelIndex].host = e.target.value;
        if (!isInitializing) {
          handleUnsavedChanges(true, 'Host has been modified. Please save your changes.');
          updateJsonTextarea();
        }
      });

      const portInput = channelDiv.querySelector(`.${channelType}-port-input`);
      portInput.addEventListener('change', (e) => {
        jsonData[channelType][channelIndex].port = e.target.value;
        if (!isInitializing) {
          handleUnsavedChanges(true, 'Port has been modified. Please save your changes.');
          updateJsonTextarea();
        }
      });

      const descriptionInput = channelDiv.querySelector(`.${channelType}-description-input`);
      descriptionInput.addEventListener('change', (e) => {
        jsonData[channelType][channelIndex].description = e.target.value;
        if (!isInitializing) {
          handleUnsavedChanges(true, 'Description has been modified. Please save your changes.');
          updateJsonTextarea();
        }
      });

      const activeCheckbox = channelDiv.querySelector(`.${channelType}-active-checkbox`);
      activeCheckbox.addEventListener('change', (e) => {
        jsonData[channelType][channelIndex].active = e.target.checked;
        if (!isInitializing) {
          handleUnsavedChanges(true, 'Active status has been modified. Please save your changes.');
          updateJsonTextarea();
        }
      });

      const deleteBtn = channelDiv.querySelector(`.${channelType}-delete-channel-btn`);
      deleteBtn.addEventListener('click', () => {
        deleteChannel(channelType, channelIndex);
      });

      // Toggle Properties Button
      const togglePropertiesBtn = channelDiv.querySelector(`.${channelType}-toggle-properties-btn`);
      togglePropertiesBtn.addEventListener('click', () => {
        propertiesContainer.classList.toggle('hidden');
        const chevronIcon = togglePropertiesBtn.querySelector('svg');
        // Update the chevron icon rotation based on the visibility
        if (propertiesContainer.classList.contains('hidden')) {
          chevronIcon.classList.remove('transform', 'rotate-180');
          openPropertiesChannels.delete(openChannelKey);
        } else {
          chevronIcon.classList.add('transform', 'rotate-180');
          openPropertiesChannels.add(openChannelKey);
        }
      });

      // Append the channel to the container
      container.appendChild(channelDiv);
    });
  } else {
    alert(`No ${channelType.toUpperCase()} channels found in JSON data.`);
  }

  isInitializing = false; // End initialization
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

  // Attach event listener to remove property
  badge.querySelector(`.${channelType}-remove-property-btn`).addEventListener('click', () => {
    removeChannelProperty(channelType, channelIndex, key);
    // Ensure properties container remains visible after removal
    openPropertiesChannels.add(`${channelType}-${channelIndex}`);
    updateSaveButton();
  });

  // Attach event listener to edit property
  badge.querySelector(`.${channelType}-edit-property-btn`).addEventListener('click', () => {
    editChannelProperty(channelType, channelIndex, key);
    // Ensure properties container remains visible after editing
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

  // Add a new channel with default values
  jsonData[channelType].push({
    host: "",
    port: "",
    active: true,
    description: ""
    // You can add more default properties here if needed
  });

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

// Generic function to handle unsaved changes and update status messages
function handleUnsavedChanges(isUnsaved, message = 'You have unsaved changes.') {
  unsavedChanges = isUnsaved;
  updateSaveButton();

  if (unsavedChanges) {
    updateStatusMessage('warning', message);
    window.addEventListener('beforeunload', beforeUnloadHandler);
  } else {
    // Only show success message if restart is required
    if (restartRequired) {
      updateStatusMessage('good', 'Changes saved. They will take effect after restarting AIS-catcher.');
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

  statusMessageDiv.innerHTML = `
    <div class="flex items-center">
      <span>${escapeHtml(message)}</span>
    </div>
  `;

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
        updateStatusMessage('good', 'Valid Sharing Key entered.');
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

function setupSharingToggle() {
  const sharingToggle = document.getElementById('sharing-toggle');
  const sharingKeyContainer = document.getElementById('sharing-key-container');

  // Initialize the visibility based on the current state in jsonData
  if (jsonData && typeof jsonData.sharing !== 'undefined') {
    sharingToggle.checked = jsonData.sharing || false;
    toggleSharingKeyInput(sharingToggle.checked);
  }

  // Event listener for the toggle
  sharingToggle.addEventListener('change', (e) => {
    const isEnabled = e.target.checked;
    toggleSharingKeyInput(isEnabled);

    // Update jsonData
    if (!jsonData.sharing) {
      jsonData.sharing = {};
    }
    jsonData.sharing = isEnabled;

    handleUnsavedChanges(true, 'Sharing settings have been modified. Please save your changes.');
    updateJsonTextarea();
  });
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

  // Parse JSON content
  try {
    jsonData = JSON.parse(jsonTextarea.innerText);
  } catch (e) {
    alert("Invalid JSON format. Please check the JSON content.");
    console.error("JSON Parse Error:", e);
    return;
  }

  setupSharingToggle();
  setupSharingKeyInput();

  // Update the Register button state after initialization
  updateRegisterButtonState();

  isInitializing = false; // End initialization
}

function openDeviceSelectionModal() {
  const deviceSelectionModal = document.getElementById('device-selection-modal');
  deviceSelectionModal.classList.remove('hidden');
  fetchDeviceList();
}

// Function to close the device selection modal
function closeDeviceSelectionModal() {
  const deviceSelectionModal = document.getElementById('device-selection-modal');
  deviceSelectionModal.classList.add('hidden');
}

// Function to fetch the device list from the server
function fetchDeviceList() {
  const deviceList = document.getElementById('device-list');
  fetch('/device-list') // Ensure this endpoint matches your server's route
    .then(response => {
      if (!response.ok) {
        throw new Error('Failed to fetch device list.');
      }
      return response.json();
    })
    .then(data => {
      populateDeviceList(data.devices);
    })
    .catch(error => {
      console.error('Error fetching device list:', error);
      deviceList.innerHTML = `<li class="text-red-500">Error fetching device list.</li>`;
    });
}

// Function to populate the device list in the modal
function populateDeviceList(devices) {
  const deviceList = document.getElementById('device-list');
  deviceList.innerHTML = ''; // Clear existing list

  if (!Array.isArray(devices) || devices.length === 0) {
    deviceList.innerHTML = `<li class="text-gray-500">No devices found.</li>`;
    return;
  }

  devices.forEach(device => {
    const listItem = document.createElement('li');
    listItem.className = 'flex items-center justify-between p-2 border rounded-md hover:bg-gray-100 cursor-pointer';
    listItem.innerHTML = `
      <span>${escapeHtml(device.name)}</span>
      <button type="button" class="select-device-btn bg-blue-500 text-white px-2 py-1 rounded-md hover:bg-blue-600">Select</button>
    `;

    // Attach event listener to the Select button
    listItem.querySelector('.select-device-btn').addEventListener('click', () => {
      selectDevice(device);
      closeDeviceSelectionModal();
    });

    deviceList.appendChild(listItem);
  });
}

// Function to handle device selection
function selectDevice(device) {
  if (!device || typeof device !== 'object') {
    console.error('Invalid device selected:', device);
    return;
  }


  const deviceInput = document.getElementById('device-input');
  const serialKeyInput = document.getElementById('serial-key');

  // Populate the device input and serial key fields
  deviceInput.value = device.input ? capitalizeFirstLetter(device.input.toLowerCase()) : '';
  serialKeyInput.value = device.serial || '';

  // Update jsonData accordingly
  // Ensure consistency in JSON keys. Here, assuming 'device_input' and 'serial_key'
  jsonData.input = device.input || '';
  jsonData.serial = device.serial || '';

  // Handle unsaved changes and update JSON display
  handleUnsavedChanges(true, 'Device selection has been updated. Please save your changes.');
  updateJsonTextarea();
}

// Function to initialize the device input and serial key fields
function initializeInputSelection() {
  // Initialize the device input and serial key fields
  const deviceInput = document.getElementById('device-input');
  const serialKeyInput = document.getElementById('serial-key');

  if (!deviceInput || !serialKeyInput) return;

  // Initialize the input based on jsonData
  if (jsonData.input) {
    deviceInput.value = jsonData.input;
  }

  if (jsonData.serial) {
    serialKeyInput.value = jsonData.serial;
  }

  // Event listener for the device input field
  deviceInput.addEventListener('change', (e) => {
    const input = e.target.value.trim();
    jsonData.input = input;

    handleUnsavedChanges(true, 'Device input has been modified. Please save your changes.');
    updateJsonTextarea();
  });

  // Event listener for the serial key field
  serialKeyInput.addEventListener('change', (e) => {
    const serial = e.target.value.trim();
    jsonData.serial = serial;

    handleUnsavedChanges(true, 'Serial key has been modified. Please save your changes.');
    updateJsonTextarea();
  });
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
    initializeSharingChannel();
    initializeInputSelection();
    updateJsonTextarea();
  }
});


// Check if the save button exists
if (saveButton) {
  // Add event listener to the save button
  saveButton.addEventListener('click', function (e) {
    e.preventDefault(); // Prevents default action, if any
    saveData();
  });
} else {
  console.warn("Save button with ID 'save-button' was not found in the DOM.");
}
