#include <stdinc.h>
#include <client.h>
#include <modules.h>
#include <hook.h>
#include <s_user.h>
#include <numeric.h>
#include <rb_lib.h>
#include <s_conf.h>

static const char msg_common_desc[] =
	"Adds user mode +G to allow messages from users with a channel in common";

static void hook_message(void *);
static void hook_invite(void *);
static void hook_umode(void *);

static mapi_hfn_list_av1 msg_common_hfnlist[] = {
	{ "privmsg_user", hook_message, HOOK_NORMAL },
	{ "invite", hook_invite, HOOK_NORMAL },
	{ "umode_changed", hook_umode, HOOK_NORMAL },
	{ NULL, NULL, 0 }
};

static int
_modinit(void)
{
	user_modes['G'] = find_umode_slot();
	construct_umodebuf();

	return user_modes['G'] != 0;
}

static void
_moddeinit(void)
{
	user_modes['G'] = 0;
	construct_umodebuf();
}

static bool
have_common_channel(struct Client *a, struct Client *b)
{
	rb_dlink_node *ptr;
	struct membership *msptr;

	RB_DLINK_FOREACH(ptr, a->user->channel.head)
	{
		msptr = ptr->data;
		if (IsMember(b, msptr->chptr))
			return true;
	}
	return false;
}

static bool
allow_msg(struct Client *source_p, struct Client *target_p, bool quiet)
{
	if (accept_message(source_p, target_p))
		return true;
	if (have_common_channel(source_p, target_p))
		return true;

	if (!quiet)
	{
		sendto_one_numeric(source_p, ERR_TARGUMODEG,
				"%s :is in +G mode and you have no channels in common.",
				target_p->name);
	}

	if ((target_p->localClient->last_caller_id_time +
			ConfigFileEntry.caller_id_wait) < rb_current_time())
	{
		if (!quiet)
			sendto_one_numeric(source_p, RPL_TARGNOTIFY,
					form_str(RPL_TARGNOTIFY),
					target_p->name);

		add_reply_target(target_p, source_p);
		sendto_one(target_p, form_str(RPL_UMODEGMSG),
				me.name, target_p->name, source_p->name,
				source_p->username, source_p->host);

		target_p->localClient->last_caller_id_time = rb_current_time();
	}

	return false;
}

static void
hook_message(void *data_)
{
	hook_data_privmsg_user *data = data_;

	if (MyClient(data->source_p) && (data->source_p->umodes & user_modes['G']))
	{
		/* XXX do the implicit /accept */
		if (data->msgtype != MESSAGE_TYPE_NOTICE &&
				(!accept_message(data->target_p, data->source_p)) || IsOper(data->target_p))
		{
			if(rb_dlink_list_length(&data->source_p->localClient->allow_list) <
					(unsigned long)ConfigFileEntry.max_accept)
			{
				rb_dlinkAddAlloc(data->target_p, &data->source_p->localClient->allow_list);
				rb_dlinkAddAlloc(data->source_p, &data->target_p->on_allow_list);
			}
			else
			{
				sendto_one_numeric(data->source_p, ERR_OWNMODE,
						form_str(ERR_OWNMODE),
						data->target_p->name, "+g");
				data->approved = 1;
				return;
			}
		}
	}

	if (!MyClient(data->target_p))
		return;
	if (!(data->target_p->umodes & user_modes['G']))
		return;
	/* we're not going to approve an already rejected message */
	if (data->approved != 0)
		return;

	if (!allow_msg(data->source_p, data->target_p, data->msgtype == MESSAGE_TYPE_NOTICE))
		data->approved = 1;
}

static void
hook_invite(void *data_)
{
	hook_data_channel_approval *data = data_;

	if (!MyClient(data->target))
		return;
	if (!(data->target->umodes & user_modes['G']))
		return;
	if (!data->approved)
		return;

	if (!allow_msg(data->client, data->target, false))
		data->approved = 0;
}

static void
hook_umode(void *data_)
{
	hook_data_umode_changed *data = data_;
	unsigned int gg = user_modes['G'] | user_modes['g'];
	unsigned int add = data->client->umodes & ~data->oldumodes;

	if ((data->client->umodes & gg) != gg)
		return;

	/* it doesn't make sense to have +G and +g
	 * if we added exactly one of them, keep that one
	 */
	if (!(add & user_modes['G']) != !(add & user_modes['g']))
	{
		data->client->umodes &= ~(add & gg);
		return;
	}

	/* otherwise just leave +g since it's broader */
	data->client->umodes &= ~user_modes['G'];
}

DECLARE_MODULE_AV2(umode_msg_common_channel, _modinit, _moddeinit, NULL, NULL, msg_common_hfnlist, NULL, NULL, msg_common_desc);
