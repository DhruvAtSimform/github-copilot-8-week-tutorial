/**
 * Timezone Explorer - Client-side JavaScript
 * Handles country selection and timezone fetching
 */

// DOM elements
const countrySelect = document.getElementById('country-select');
const timezoneForm = document.getElementById('timezone-form');
const resultsContainer = document.getElementById('results-container');
const timezoneList = document.getElementById('timezone-list');
const countryName = document.getElementById('country-name');
const errorMessage = document.getElementById('error-message');

// Store countries data
let countriesData = {};

/**
 * Fetch available countries from the API
 */
async function fetchCountries() {
    try {
        const response = await fetch('/api/timezones/countries');

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        if (data.status === 'success' && data.data.countries) {
            countriesData = data.data.countries;
            populateCountrySelect(data.data.countries);
        } else {
            throw new Error('Invalid response format');
        }
    } catch (error) {
        console.error('Error fetching countries:', error);
        showError('Failed to load countries. Please refresh the page.');

        // Safely create error option
        countrySelect.innerHTML = '';
        const errorOption = document.createElement('option');
        errorOption.value = '';
        errorOption.textContent = 'Error loading countries';
        countrySelect.appendChild(errorOption);
    }
}

/**
 * Populate the country select dropdown
 * 
 * @param {Object} countries - Countries object with country codes as keys
 */
function populateCountrySelect(countries) {
    // Create an array of country entries and sort by name
    const countryEntries = Object.entries(countries).sort((a, b) =>
        a[1].name.localeCompare(b[1].name)
    );

    // Clear existing options using safe method
    countrySelect.innerHTML = ''; // Clear all options

    // Add default option safely
    const defaultOption = document.createElement('option');
    defaultOption.value = '';
    defaultOption.textContent = '-- Select a Country --';
    countrySelect.appendChild(defaultOption);

    // Add country options
    countryEntries.forEach(([code, info]) => {
        const option = document.createElement('option');
        option.value = code;
        option.textContent = `${info.name} (${info.timezoneCount} timezone${info.timezoneCount > 1 ? 's' : ''})`;
        countrySelect.appendChild(option);
    });
}

/**
 * Fetch timezones for a selected country
 * 
 * @param {string} countryCode - Country code (e.g., 'US', 'IN')
 */
async function fetchTimezones(countryCode) {
    try {
        // Show loading state
        const submitButton = timezoneForm.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.textContent = 'Loading...';
        submitButton.classList.add('loading');

        const response = await fetch(`/api/timezones?countryCode=${countryCode}`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        if (data.status === 'success' && data.data.timezones) {
            displayTimezones(data.data);
            hideError();
        } else {
            throw new Error('Invalid response format');
        }
    } catch (error) {
        console.error('Error fetching timezones:', error);
        showError('Failed to fetch timezones. Please try again.');
        hideResults();
    } finally {
        // Reset button state
        const submitButton = timezoneForm.querySelector('button[type="submit"]');
        submitButton.disabled = false;
        submitButton.textContent = 'Get Timezones';
        submitButton.classList.remove('loading');
    }
}

/**
 * Display fetched timezones in the UI (XSS-safe implementation)
 * 
 * @param {Object} data - Response data containing timezones
 */
function displayTimezones(data) {
    const country = countriesData[data.countryCode];
    const countryDisplayName = country ? country.name : data.countryCode;

    // Update country name using textContent (XSS-safe)
    countryName.textContent = countryDisplayName;

    // Clear previous results safely
    timezoneList.innerHTML = '';

    // Check if timezones exist
    if (!data.timezones || data.timezones.length === 0) {
        // Create no results message safely
        const noResults = document.createElement('p');
        noResults.className = 'no-results';
        noResults.textContent = 'No timezones found for this country.';
        timezoneList.appendChild(noResults);
        resultsContainer.classList.remove('hidden');
        return;
    }

    // Create timezone items safely using DOM API
    data.timezones.forEach((timezone, index) => {
        const timezoneItem = document.createElement('div');
        timezoneItem.className = 'timezone-item';
        timezoneItem.style.animationDelay = `${index * 0.1}s`;

        const timezoneName = document.createElement('div');
        timezoneName.className = 'timezone-name';
        timezoneName.textContent = timezone.name; // XSS-safe: textContent escapes HTML

        const timezoneOffset = document.createElement('div');
        timezoneOffset.className = 'timezone-offset';
        timezoneOffset.textContent = `UTC ${timezone.offset >= 0 ? '+' : ''}${timezone.offset}`;

        timezoneItem.appendChild(timezoneName);
        timezoneItem.appendChild(timezoneOffset);
        timezoneList.appendChild(timezoneItem);
    });

    // Show results
    resultsContainer.classList.remove('hidden');

    // Smooth scroll to results
    setTimeout(() => {
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
}

/**
 * Show error message
 * 
 * @param {string} message - Error message to display
 */
function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');
}

/**
 * Hide error message
 */
function hideError() {
    errorMessage.classList.add('hidden');
}

/**
 * Hide results container
 */
function hideResults() {
    resultsContainer.classList.add('hidden');
}

/**
 * Handle form submission
 * 
 * @param {Event} event - Form submit event
 */
function handleFormSubmit(event) {
    event.preventDefault();

    const countryCode = countrySelect.value;

    if (!countryCode) {
        showError('Please select a country first.');
        return;
    }

    hideError();
    fetchTimezones(countryCode);
}

// Event listeners
timezoneForm.addEventListener('submit', handleFormSubmit);

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    fetchCountries();
});
