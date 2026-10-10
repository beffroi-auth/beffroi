/*
 * The browser side of a push subscription (Push API §4, architecture §5.2, §5.6): the page of the
 * account names, in data-application-server-key, the public half of the application server key of the
 * tenant (RFC 8292 §3.2) and, in data-worker-url, the service worker that will receive. Opening the page
 * registers that worker; pressing the button asks the user for permission, subscribes to their own push
 * service, writes the endpoint and the two keys the subscription carries into the hidden fields of the form
 * and submits it, so that the answer is a redirection the browser follows, as with every other form of
 * these pages.
 *
 * Opening the page also says which row is this browser, when one of them is: the page carries the digest
 * of the endpoint of every browser it lists, which is what this provider recognises one by, and the digest
 * of what this browser holds is computed here. A browser that is already listed is not offered the button
 * that associates it; one whose row is on another page of the list is, and pressing it writes the row it
 * already has rather than a second one.
 *
 * The worker is registered when the page opens and not only when somebody subscribes, because a
 * registration can go without the subscription going with it: a browser whose site data was cleared keeps
 * neither, but one where the worker alone was removed still holds its subscription, and its push service
 * still takes messages for it. There is nothing then to show them: a push with no registered worker is
 * dropped by the browser, and this provider is answered that the message was taken all the same. So the
 * page whose subject is which browsers may be reached makes sure this one can receive, every time it is
 * opened.
 *
 * Three things fail here for three reasons, and each is said in the paragraph of the page that names the
 * same one: the notifications were not allowed ("permission"), the worker that would receive could not be
 * installed ("worker"), the push service of this browser refused the subscription ("subscription"). Each
 * is somebody else's to act on, a permission to give back, a certificate to trust, a push service to
 * reach, so none of them is said in the words of the others. A worker that failed to register is
 * registered again at the next press rather than answered with the refusal of the first.
 *
 * Nothing is loaded from anywhere else, and nothing of a subscription reaches this provider but what the
 * form posts.
 */
(() => {
    'use strict';

    const form = document.querySelector('form[data-push="subscribe"]');
    if (!form) {
        return;
    }

    const supported = 'serviceWorker' in navigator
        && 'PushManager' in window
        && typeof Notification === 'function';

    const unsupported = document.querySelector('[data-push-unsupported]');

    if (!supported || !form.dataset.applicationServerKey) {
        if (unsupported) {
            unsupported.hidden = false;
        }

        return;
    }

    form.hidden = false;
    if (unsupported) {
        unsupported.hidden = true;
    }

    /* RFC 8292 §3.2: the uncompressed point, base64url, as the bytes the Push API takes. */
    const bytesOf = (base64url) => {
        const padded = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const binary = window.atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
            bytes[index] = binary.charCodeAt(index);
        }

        return bytes;
    };

    const base64urlOf = (buffer) => {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        bytes.forEach((byte) => {
            binary += String.fromCharCode(byte);
        });

        return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };

    const fail = (reason) => {
        const message = form.querySelector(`[data-push-error="${reason}"]`)
            ?? document.querySelector(`[data-push-error="${reason}"]`);
        if (message) {
            message.hidden = false;
        }
    };

    const clear = () => {
        for (const message of document.querySelectorAll('[data-push-error]')) {
            message.hidden = true;
        }
    };

    /* Registered once, whether the page was opened to subscribe or to read what is subscribed. */
    let registering = null;
    const worker = () => {
        registering ??= navigator.serviceWorker
            .register(form.dataset.workerUrl)
            .then(async (registration) => {
                await navigator.serviceWorker.ready;

                return registration;
            })
            .catch((error) => {
                registering = null;

                throw error;
            });

        return registering;
    };

    /* A failure here is said when somebody presses the button, which is the only moment it is theirs to act on. */
    worker().catch(() => {});

    /* The hex SHA-256 of an endpoint, which is what a row of the page carries (PushSubscription::digestOf):
       an endpoint is as long as its push service decided, and comparing a digest compares the whole of it. */
    const digestOf = async (endpoint) => {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));

        return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
    };

    /* Which row is this browser, if this browser is one of them: what it holds is its own subscription,
       which this provider may have been told of or not. A browser the user took out holds one that matches
       no row, and is offered the button again. */
    const recognise = async () => {
        const subscription = await (await worker()).pushManager.getSubscription();
        if (!subscription) {
            return;
        }
        const row = document.querySelector(`tr[data-endpoint="${await digestOf(subscription.endpoint)}"]`);
        if (!row) {
            return;
        }
        const marker = row.querySelector('[data-subscription-current]');
        if (marker) {
            marker.hidden = false;
        }
        row.dataset.current = 'yes';
        form.hidden = true;
    };

    recognise().catch(() => {});

    form.querySelector('[data-push-button]').addEventListener('click', async () => {
        clear();

        let permission;
        try {
            permission = await Notification.requestPermission();
        } catch {
            fail('permission');

            return;
        }
        if (permission !== 'granted') {
            fail('permission');

            return;
        }

        let registration;
        try {
            registration = await worker();
        } catch {
            fail('worker');

            return;
        }

        try {
            const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: bytesOf(form.dataset.applicationServerKey),
            });
            form.querySelector('input[name="endpoint"]').value = subscription.endpoint;
            form.querySelector('input[name="p256dh"]').value = base64urlOf(subscription.getKey('p256dh'));
            form.querySelector('input[name="auth"]').value = base64urlOf(subscription.getKey('auth'));
            form.submit();
        } catch {
            fail('subscription');
        }
    });
})();
