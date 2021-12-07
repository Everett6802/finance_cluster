#ifndef SYSTEM_OPERATOR_H
#define SYSTEM_OPERATOR_H

#include "common.h"


class SystemOperator : public INotify
{
	DECLARE_MSG_DUMPER()
private:
	PINOTIFY observer;

public:
	SystemOperator(PINOTIFY notify);
	virtual ~SystemOperator();

	unsigned short initialize();
	unsigned short deinitialize();

// INotify
	virtual unsigned short notify(NotifyType notify_type, void* param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};

typedef SystemOperator* PSYSTEM_OPERATOR;

#endif