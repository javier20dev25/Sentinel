/**
 * Safe Example Component
 * This file contains standard, non-malicious logic.
 */

function calculateTotal(items) {
    return items.reduce((sum, item) => sum + item.price, 0);
}

const checkoutData = {
    userId: 'user_123',
    items: [
        { name: 'Paper Plane', price: 15.00 },
        { name: 'Toy Rocket', price: 45.00 }
    ]
};

console.log('Total cost:', calculateTotal(checkoutData.items));
