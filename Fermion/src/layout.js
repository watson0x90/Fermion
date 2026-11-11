// @ts-check
// Output/editor split layout: toggle vertical<->horizontal, persist the
// choice, keep the toolbar icon in sync, and adjust the search box to the
// sidebar width. Owns the live `isVertical` state. The split library (Split)
// is a page global from split-1.6.4.js; window.split is the shared instance.
//
// createLayout(deps) wires the module to the rest of the app without importing
// it: deps.getTerminal()/getEditor() return the live terminal/Monaco handles,
// deps.onChange() persists settings (today's saveSettings).
function createLayout(deps) {
	// App starts vertical; toggleLayout() flips this and rebuilds the split.
	let isVertical = true;

	// #FridaOut exists by the time createLayout runs (DOMContentLoaded), so
	// capture it once; toggleLayout references it verbatim below.
	const fridaOut = document.getElementById('FridaOut');

	const verticalIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
  <line x1="12" y1="3" x2="12" y2="21"></line>
</svg>`;

	const horizontalIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
  <line x1="3" y1="12" x2="21" y2="12"></line>
</svg>`;

	// Toggle layout direction
	function toggleLayout() {
		// Toggle the layout state
		isVertical = !isVertical;

		// Ensure split instance exists
		if (typeof window.split !== 'undefined') {
			// Get elements we'll need to manipulate
			const split0 = document.getElementById('split-0');
			const split1 = document.getElementById('split-1');
			const container = document.getElementById('container');
			const fridaOutContainer = /** @type {HTMLElement} */ (document.querySelector('.textarea-container'));
			const splitContainer = document.querySelector('.split');

			// Force visibility of the output area during transition
			fridaOut.style.display = 'block';

			// Destroy existing split
			window.split.destroy();

			// Remove all inline styles that might interfere
			split0.removeAttribute('style');
			split1.removeAttribute('style');

			// Apply basic required styles
			split0.style.overflow = 'hidden';
			split1.style.overflow = 'hidden';
			container.style.width = '100%';
			container.style.height = '100%';

			// Update container classes
			if (isVertical) {
				splitContainer.classList.remove('horizontal');
			} else {
				splitContainer.classList.add('horizontal');
			}

			// Create new split with a delay to ensure DOM updates
			setTimeout(() => {
				window.split = Split(['#split-0', '#split-1'], {
					direction: isVertical ? 'vertical' : 'horizontal',
					sizes: isVertical ? [63, 37] : [50, 50],
					minSize: 100,
					gutterSize: 8,
					onDragEnd: function () {
						window.dispatchEvent(new Event('resize'));
						const ed = deps.getEditor();
						if (ed) {
							ed.layout();
						}
					}
				});

				// Force output container to take full width/height
				fridaOutContainer.style.width = '100%';
				fridaOutContainer.style.height = '100%';
				fridaOut.style.width = '100%';
				fridaOut.style.height = '100%';

				// Force Monaco editor layout update
				const ed = deps.getEditor();
				if (ed) {
					ed.layout();
				}

				// Update layout button icon
				updateLayoutButtonIcon();

				// Refit the terminal to the new split dimensions
				const term = deps.getTerminal();
				if (term) term.fit();
			}, 50);

			// Save settings
			deps.onChange();
		}
	}

	// Function to update the layout button icon based on current state
	function updateLayoutButtonIcon() {
		const toggleButton = document.getElementById('toggle-layout');

		// Note: We've swapped the logic here - show what layout we're CURRENTLY in
		// (not what we'll switch to next)
		toggleButton.innerHTML = isVertical ? verticalIcon : horizontalIcon;
		toggleButton.title = isVertical ? "Switch to horizontal layout" : "Switch to vertical layout";
	}

	function initLayoutButton() {
		// Set the initial icon based on the current layout
		updateLayoutButtonIcon();
	}

	// Enhanced function to adjust UI based on sidebar state
	function adjustUIForSidebar() {
		// Get the actual width of the container
		const containerWidth = document.getElementById('split-1').offsetWidth;

		// Adjust search container width based on available space
		const searchContainer = /** @type {HTMLElement | null} */ (document.querySelector('.search-container'));
		if (searchContainer) {
			// Make search container narrower if space is limited
			if (containerWidth < 300) {
				searchContainer.style.maxWidth = '100px';
				searchContainer.style.minWidth = '60px';
			} else {
				searchContainer.style.maxWidth = '220px'; // Updated to accommodate navigation buttons
				searchContainer.style.minWidth = '80px';
			}
		}
	}

	return {
		toggleLayout,
		initLayoutButton,
		adjustUIForSidebar,
		isVertical: () => isVertical,
	};
}

module.exports = { createLayout };
